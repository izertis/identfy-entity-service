import {
  JWK,
  JWTPayload,
  KeyLike,
  SignJWT,
  importJWK,
} from "jose";
import { join as joinPath } from 'node:path/posix';
import fetch from 'node-fetch';
import AuthSchema from "../../api/auth/auth.schema.js";
import { autoInjectable, singleton } from "tsyringe";
import Logger from "../../../shared/classes/logger.js";
import {
  PreAuthCodeData,
} from "../../../shared/interfaces/auth.interface.js";
import { DIDDocument, Resolver } from "did-resolver";
import { getResolver as keyDidResolver } from "@cef-ebsi/key-did-resolver";
import { errorToString, removeSlash } from "../../../shared/utils/api.utils.js";
import Joi from "joi";
import {
  AuthServerMetadata,
  AuthorizationDetails,
  AuthzRequest,
  DIFPresentationDefinition,
  HolderMetadata,
  InvalidRequest,
  OpenIDReliyingParty,
  VerifiedBaseAuthzRequest,
  W3CVerifiableCredential,
  generateDefaultAuthorisationServerMetadata
} from "openid-lib";
import {
  AUTHORIZATION,
  BACKEND,
  EBSI,
  VERIFIER
} from "../../../shared/config/configuration.js";
import {
  VcScopeAction,
  VpScopeAction
} from "../../../shared/interfaces/scope-action.interface.js";
import { SUPPORTED_SIGNATURE_ALG } from "../../../shared/config/supported_alg.js";
import {
  BadRequestError,
  HttpError,
  InternalServerError
} from "../../../shared/classes/errors.js";
import {
  AuthzErrorCodes
} from "../../../shared/constants/error_codes.constants.js";
import {
  VERIFIABLE_ATTESTATION_TYPE,
  VERIFIABLE_CREDENTIAL_TYPE
} from "../../../shared/constants/credential.constants.js";
import { URLSearchParams } from "url";
import {
  NonceAuthState,
  NonceResponse,
  ResponseTypeOpcode
} from "../../../shared/interfaces/nonce.interface.js";
import { JwtHeader, JwtPayload } from "jsonwebtoken";
import { getResolver as ebsiDidResolver } from "@cef-ebsi/ebsi-did-resolver";
import { TokenType } from "./auth.service.js";
import { checkCredentialStatus } from "./checks/credential_status/index.js";
import { checkTrustChain } from "./checks/terms_of_use/index.js";
import { authBackend } from "../../../shared/utils/functions/auth.utils.js";

@singleton()
@autoInjectable()
export default class AuthRules {
  constructor(private logger: Logger, private authSchema: AuthSchema) { }

  didResolver = new Resolver({
    ...keyDidResolver(),
    ...ebsiDidResolver({
      registry: EBSI.did_registry,
    })
  });

  /**
   * Generate a callback that, given a payload, generates a JWT
   * @param privateKey The private key to use
   * @param publicKeyJwk The public key related to the private key
   * @param pubKeyThumbprint The thumbprint of the public key
   * @returns A function that is able to generate JWTs
   */
  generateJwt(
    privateKey: KeyLike | Uint8Array,
    publicKeyJwk: JWK,
    pubKeyThumbprint: string,
  ) {
    return async (payload: JWTPayload, _algs: any) => {
      const header = {
        typ: "JWT",
        alg: publicKeyJwk.alg || SUPPORTED_SIGNATURE_ALG,
        kid: publicKeyJwk.kid || pubKeyThumbprint,
      };
      return await new SignJWT(payload)
        .setProtectedHeader(header)
        .setIssuedAt()
        .sign(privateKey);
    }
  }

  /**
   * Generate a callback that can be used to check the nonce of a ID Token
   * @param nonceState The state associated with a nonce
   * @param nonceResponse The nonce response received from the nonce service
   * @returns A function that can be used to check nonces
   */
  checkNonceCallbackIdToken(
    nonceState: NonceAuthState,
    nonceResponse: NonceResponse
  ) {
    return async (
      header: JwtHeader,
      payload: JwtPayload,
      didDocument: DIDDocument
    ) => {
      if (payload.scope && payload.scope !== nonceState.scope) {
        return { valid: false, error: "The scope specified is invalid" };
      }

      if (!header.kid) {
        return { valid: false, error: "JWT has not KID" };
      }
      if (nonceResponse.did != "") {
        let clientId = nonceResponse.did;

        if (nonceState.serviceJwk) {
          clientId = payload.sub!;
        }

        if (clientId != payload.iss) {
          return {
            valid: false,
            error: "The nonce specified and the issuer of the token are not correlated"
          };
        }

      }
      return { valid: true };
    }
  }

  /**
   * Generate a callback that can be used to verify the nonce of a VP Token
   * @param nonceResponse The nonce response received from the nonce service
   * @returns A function that can be used to check the nonce of a VP Token
   */
  checkNonceCallbackVpToken(
    nonceState: NonceAuthState,
    nonceResponse: NonceResponse
  ) {
    return async (subject: string, jwtNonce: string) => {
      if (nonceResponse.did != "null") {
        let clientId = nonceResponse.did;

        if (nonceState.serviceJwk) {
          clientId = subject;
        }

        if (clientId != subject) {
          return {
            valid: false,
            error: "The nonce specified and the issuer of the token are not correlated"
          };
        }
      }
      return { valid: true };
    }
  }

  /**
   * Generate the instance of a RP
   * @param issuer The issuer identifier
   * @returns An instance of a RP
   */
  buildRp = (
    issuer: string
  ): OpenIDReliyingParty => {
    return new OpenIDReliyingParty(
      async () => this.generateClientMetadata(this.authSchema.client_metadata),
      this.getIssuerMetadata(issuer),
      this.didResolver,
      async (vc: W3CVerifiableCredential) => {
        let result = await checkCredentialStatus(vc);
        if (!result.valid) {
          return result;
        }
        if (EBSI.verify_terms_of_use) {
          result = await checkTrustChain(vc);
        }
        return result;
      }
    );
  }

  verifyToken = async (
    rp: OpenIDReliyingParty,
    token: string,
    tokenType: TokenType,
    nonceState: NonceAuthState,
    nonceResponse: NonceResponse,
    presentationDefinition?: DIFPresentationDefinition,
    presentationSubmission?: string
  ) => {
    if (tokenType === TokenType.ID) {
      const verifiedIdTokenResponse = await rp.verifyIdTokenResponse(
        {
          id_token: token,
        },
        this.checkNonceCallbackIdToken(nonceState, nonceResponse)
      );
      return { holderDid: verifiedIdTokenResponse.didDocument.id };
    } else {
      if (!presentationSubmission) {
        throw new InvalidRequest("A presentation submission is needed");
      }
      const submission = JSON.parse(presentationSubmission);
      this.logger.info("Verify VP Token");
      const verifiedVpTokenResponse = await rp.verifyVpTokenResponse(
        {
          vp_token: token,
          presentation_submission: submission
        },
        presentationDefinition!,
        this.checkNonceCallbackVpToken(nonceState, nonceResponse),
      );

      return {
        holderDid: verifiedVpTokenResponse.vpInternalData.holderDid,
        claimsData: verifiedVpTokenResponse.vpInternalData.claimsData
      };
    }
  }

  getScopeAction = async (
    entityUri: string,
    nonceState: NonceAuthState
  ) => {
    const scopeAction = nonceState.opcode === ResponseTypeOpcode.ISSUANCE ?
      await this.getIssuanceInfo(
        entityUri,
        nonceState.type!
      ) :
      await this.getVerificationInfo(
        entityUri,
        nonceState.scope
      );
    return scopeAction;
  }

  /**
   * Allows to recover ScopeAction information for the issuance process
   * @param issuerUri The URI of the issuer
   * @param types The specific type of a credential
   * @returns The information associated with a specific issuance process
   */
  getIssuanceInfo = async (
    issuerUri: string,
    types: string | string[]
  ): Promise<VcScopeAction> => {
    // Auth Service into the Backend first --> Obtain a JWT (Auth)
    const authorize = await authBackend();
    const uniqueType = Array.isArray(types) ? types.find((type) => {
      return (type !== VERIFIABLE_CREDENTIAL_TYPE &&
        type !== VERIFIABLE_ATTESTATION_TYPE);
    }) : types;
    if (!uniqueType) {
      throw new BadRequestError(
        "Invalid VC type specified", AuthzErrorCodes.INVALID_REQUEST
      );
    }
    const tmp = issuerUri.split("/");
    const issuerId = tmp[tmp.length - 1];
    const params = new URLSearchParams(Object.entries({
      credential_types: uniqueType,
      issuer: issuerId
    })).toString();
    const url = new URL(BACKEND.url);
    url.pathname = joinPath(BACKEND.issuance_flow_path)
    const data = await fetch(`${url.toString()}?${params}`,
      {
        method: 'GET',
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer " + authorize
        },
      });
    return await data.json() as VcScopeAction;
  }

  /**
   * Allows to recover ScopeAction information for the verification process
   * @param verifierUri The URI of the verifier
   * @param scope The scope of the verification process
   * @returns The information associated with a specific verification process
   */
  getVerificationInfo = async (
    verifierUri: string,
    scope: string
  ): Promise<VpScopeAction> => {
    const authorize = await authBackend();
    const tmp = verifierUri.split("/");
    const issuerId = tmp[tmp.length - 1];
    const params = new URLSearchParams(Object.entries({
      scope,
      verifier: issuerId
    })).toString();
    const url = new URL(BACKEND.url);
    url.pathname = joinPath(BACKEND.verification_flow_path)
    const data = await fetch(`${url.toString()}?${params}`, {
      method: 'GET',
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + authorize
      },
    });
    return await data.json() as VpScopeAction;
  }

  /**
   * Generate an authz code in JWT format
   * @param nonce The nonce to include in the JWT
   * @param privateKey The private key to use to sign the token
   * @param kid The kid to include in the header of the JWT
   * @param subject The subject of the token
   * @param issuer The issuer of the token
   * @param scope The scope to include in the JWT
   * @param type The credential type requested by a client
   * @returns A JWT in string format
   */
  generateAuthzCode = async (
    nonce: string,
    privateKey: KeyLike | Uint8Array,
    alg: string,
    kid: string,
    subject: string,
    issuer: string,
    scope: string,
    type?: string
  ): Promise<string> => {
    const header = {
      alg,
      kid,
    };
    const payload: Record<string, string> = {
      nonce, scope
    };
    if (type) {
      payload.type = type;
    }
    return await new SignJWT(payload)
      .setProtectedHeader(header)
      .setSubject(subject)
      .setAudience(issuer)
      .setExpirationTime("15m")
      .setIssuer(issuer)
      .sign(privateKey);
  }

  /**
   * Allows to generate an error to be used in a redirect response.
   *
   * @param uri The redirect URI.
   * @param code The error identifier code.
   * @param description The error description.
   * @returns The HTTP Status to use among the location to use with the error
  */
  generateLocationErrorResponse = (
    uri: string,
    code: string,
    description: string,
    state?: string
  ) => {
    const params: Record<string, any> = {
      error_description: description,
      error: code
    }
    if (state) {
      params.state = state;
    }
    return {
      status: 302, location: this.buildRedirectResponse(
        uri,
        new URLSearchParams(params).toString()
      )
    };
  }

  /**
   * Verify an Authz Request with "code" as response_type
   * @param rp The RP instance that will perform a basic verification of the request
   * @param authRequest The request to verify
   * @param expectedScope The scope expected to be included in the request
   * @returns Verified data of the request
   */
  async verifyBaseAuthzRequest(
    rp: OpenIDReliyingParty,
    authRequest: AuthzRequest,
    expectedScope?: string
  ): Promise<VerifiedBaseAuthzRequest> {
    const verifiedAuthz = await rp.verifyBaseAuthzRequest(
      authRequest,
      {
        scopeVerifyCallback: expectedScope ? async (scope) => {
          if (scope === expectedScope) {
            return { valid: true };
          } else {
            return { valid: false, error: "Invalid scope specified" };
          }
        } : undefined
      }
    );
    return verifiedAuthz;
  }

  /**
   * Allows to generate a HTTP location.
   *
   * @param redirectUri The redirect URI.
   * @param params The params to concatenate in the URI.
   * @returns The location URI to use
  */
  buildRedirectResponse = (
    redirectUri: string,
    params: string
  ): string => {
    const hasParams = redirectUri!.includes("?");
    const redirect_uri = hasParams ?
      redirectUri :
      redirectUri?.endsWith("/") ?
        redirectUri :
        `${redirectUri}/`;
    return `${redirect_uri}${hasParams ? "&" : "/?"}${params}`;
  }

  /**
   * Parses private and public keys in JWK format.
   *
   * @param privateKeyStr - Optional. The private key string in JWK format.
   * @param publicKeyStr - Optional. The public key string in JWK format.
   * @returns An object containing the parsed JWK and key-like representations of the private and public keys.
   * @throws Error if at least one key is not provided or if there are errors parsing the keys.
   */
  parseKeysJwk = async (
    privateKeyStr?: string,
    publicKeyStr?: string
  ): Promise<{
    jwk: { privateKey: JWK; publicKey: JWK };
    keyLike: { privateKey: KeyLike | Uint8Array; publicKey: KeyLike | Uint8Array };
  }> => {
    if (!privateKeyStr && !publicKeyStr) {
      throw new Error("At lest one key must be provided");
    }
    let privateKeyJwk: JWK;
    let privateKey: KeyLike | Uint8Array;
    let publicKeyJwk: JWK;
    let publicKey: KeyLike | Uint8Array;
    if (privateKeyStr) {
      try {
        privateKeyJwk = JSON.parse(privateKeyStr!);
        privateKey = await importJWK(privateKeyJwk);
      } catch (error) {
        this.logger.error(errorToString(error));
        throw new Error(`Parsing private key to JWK object. ${error}`);
      }
    }
    if (publicKeyStr) {
      try {
        publicKeyJwk = JSON.parse(publicKeyStr!);
        publicKey = await importJWK(publicKeyJwk);
      } catch (error) {
        throw new Error(`Parsing public key to JWK object. ${error}`);
      }
    }

    return {
      jwk: { privateKey: privateKeyJwk!, publicKey: publicKeyJwk! },
      keyLike: { privateKey: privateKey!, publicKey: publicKey! },
    };
  };

  /**
   * Get issuer metadata configuration
   * @param issuer
   * @returns
   */
  getIssuerMetadata(issuer: string) {
    return this.ebsiAuthorisationServerMetadata(issuer);
  }

  /**
  * Generate metadata configuration for a Issuer according to EBSI
  * @param issuer The issuer identifier. It should be an URI
  * @returns Authorisation server metadata
  */
  ebsiAuthorisationServerMetadata(issuerUri: string): AuthServerMetadata {
    // Remove "/" if it comes set in the parameter
    issuerUri = removeSlash(issuerUri);
    // Destructure the AUTHORIZATION object
    const {
      issuer,
      authorization_endpoint,
      token_endpoint,
      jwks_uri
    } = AUTHORIZATION;

    const defaultValue = generateDefaultAuthorisationServerMetadata(issuerUri);

    return {
      ...defaultValue,
      "issuer": issuerUri.concat(issuer),
      "authorization_endpoint": issuerUri.concat(authorization_endpoint),
      "token_endpoint": issuerUri.concat(token_endpoint),
      "jwks_uri": issuerUri.concat(jwks_uri),
      "grant_types_supported": ["authorization_code", "urn:ietf:params:oauth:grant-type:pre-authorized_code"],
    }
  }

  /**
   * Generate the default IClientMetadata
   * @param schema Joi Schema of a ClientMetadata
   * @param issuer URI string of Auth issuer
   * @returns The default IClientMetadata
   */
  private generateClientMetadata = (
    schema: Joi.ObjectSchema<any>,
  ): HolderMetadata => {
    return {
      authorization_endpoint: schema.describe().keys.authorization_endpoint.flags.default,
      vp_formats_supported: {
        jwt_vp: {
          alg_values_supported: schema.describe().keys.vp_formats_supported.keys.jwt_vp.keys.alg_values_supported.flags.default,
        },
        jwt_vc: {
          alg_values_supported: schema.describe().keys.vp_formats_supported.keys.jwt_vc.keys.alg_values_supported.flags.default,
        }
      },
      response_types_supported: schema.describe().keys.response_types_supported.flags.default,
      scopes_supported: schema.describe().keys.scopes_supported.flags.default,
      subject_types_supported: schema.describe().keys.subject_types_supported.flags.default,
      id_token_signing_alg_values_supported: schema.describe().keys.id_token_signing_alg_values_supported.flags.default,
      request_object_signing_alg_values_supported: schema.describe().keys.request_object_signing_alg_values_supported.flags.default,
      subject_syntax_types_supported: schema.describe().keys.subject_syntax_types_supported.flags.default,
      id_token_types_supported: schema.describe().keys.id_token_types_supported.flags.default,
    };
  }

  /**
   * Validates authorization details.
   *
   * @param authDetails - The authorization details to validate.
   * @returns The validated authorization details.
   * @throws Error if validation fails.
   */
  validateAuthorizationDetails = async (authDetails?: string): Promise<AuthorizationDetails[]> => {
    // Parse the authorization details string into an object
    if (!authDetails) {
      throw new BadRequestError(
        "Invalid authorization details specified",
        AuthzErrorCodes.INVALID_REQUEST
      );
    }
    const parameters = JSON.parse(authDetails.replace(/\\/g, ""));
    // Get the authorization details schema
    const schema = this.authSchema.authorization_details;
    // Validate the parameters against the schema
    const { error, value } = schema.validate(parameters, {
      abortEarly: false,
      allowUnknown: true,
      stripUnknown: true,
    });
    // If validation fails, throw an error with details
    if (error) {
      const details = error.details;
      const label = details[0].context?.label || "";

      const root = schema.$_terms.metas[0]?.root;
      if (!root) this.logger.warn("Schema translate root not found after validation");

      const message = root && label ? `${root}.${label}` : details[0].message;
      throw new Error(`${message}. ${details}`);
    }
    // Return the validated authorization details
    return value as AuthorizationDetails[];
  };

  /**
 * Validates client metadata.
 *
 * @param clientMetadata - The client metadata to validate.
 * @returns The validated client metadata.
 * @throws Error if validation fails.
 */
  validateClientMetadata = async (clientMetadata?: string): Promise<HolderMetadata> => {
    if (!clientMetadata) {
      throw new BadRequestError(
        "Invalid authorization details specified",
        AuthzErrorCodes.INVALID_REQUEST
      );
    }
    // Parse the client metadata string into an object
    const parameters = JSON.parse(clientMetadata);
    // Get the client metadata schema
    const schema = this.authSchema.client_metadata;
    const default_metadata = this.generateClientMetadata(schema);
    const current_metadata = { ...default_metadata, ...parameters };
    // Validate the parameters against the schema
    const { error, value } = schema.validate(current_metadata, {
      abortEarly: false,
      allowUnknown: true,
      stripUnknown: true,
    });
    if (error) {
      const details = error.details;
      const label = details[0].context?.label || "";

      const root = schema.$_terms.metas[0]?.root;
      if (!root) this.logger.warn("Schema translate root not found after validation");

      const message = root && label ? `${root}.${label}` : details[0].message;
      throw new Error(`${message}. ${details}`);
    }
    return value as HolderMetadata;
  };

  /**
   * Verify the direct post request on verifier external data endpoint
   * @param valid token is valid
   * @param verifierUri The URI of the issuer
   * @param holderDid Holder DID
   * @param claimsData The data that has be verified
   * @param state State included on token
   * @returns Confirmation of the validity of the provided data
   */
  verifyOnExternalData = async (
    valid: boolean,
    verifierUri: string,
    state?: string,
    holderDid?: string,
    claimsData?: Record<string, unknown>
  ): Promise<{ verified: boolean }> => {
    try {
      const data = {
        valid,
        ...(holderDid && { holderDid }),
        ...(claimsData && { claimsData }),
        ...(state && { state }),
      };
      const fetchResponse = await fetch(
        `${verifierUri}${VERIFIER.vp_verification_endpoint}`, { headers: { "Content-Type": "application/json" }, body: JSON.stringify(data), method: "post" }
      );
      if (fetchResponse.status != 200) {
        this.logger.error(
          `An error ocurred requesting VC data: ${fetchResponse.statusText}`
        );
        throw new HttpError(
          500,
          AuthzErrorCodes.SERVER_ERROR,
          `Error requesting VP data verification`
        );
      }
      if (fetchResponse.headers.get("Content-Type") != "application/json" &&
        fetchResponse.headers.get("content-type") != "application/json") {
        this.logger.error(`VP data verification response not in JSON format`);
        throw new HttpError(
          500,
          AuthzErrorCodes.SERVER_ERROR,
          `Error requesting VP data verification`
        );
      }
      return await fetchResponse.json() as { verified: boolean };
    } catch (error: any) {
      if (error instanceof HttpError) {
        throw error;
      }
      this.logger.error(`GET VP VERIFICATION ERROR: ${error.message}`)
      throw new HttpError(
        500,
        AuthzErrorCodes.SERVER_ERROR,
        "Error requesting VP data verification"
      );
    }
  }

}
