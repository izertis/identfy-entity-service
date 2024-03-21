import {
  JWK,
  KeyLike,
  SignJWT,
  importJWK,
} from "jose";
import fetch from 'node-fetch';
import AuthSchema from "../../api/auth/auth.schema.js";
import { autoInjectable, singleton } from "tsyringe";
import Logger from "../../../shared/classes/logger.js";
import {
  PreAuthCodeData,
} from "../../../shared/interfaces/auth.interface.js";
import { Resolver } from "did-resolver";
import { getResolver } from "@cef-ebsi/key-did-resolver";
import { errorToString, removeSlash } from "../../../shared/utils/api.utils.js";
import Joi from "joi";
import {
  AuthorizationDetails,
  AuthzRequest,
  HolderMetadata,
  InvalidRequest,
  OpenIDReliyingParty,
  VerifiedBaseAuthzRequest,
  generateDefaultAuthorisationServerMetadata
} from "openid-lib";
import {
  DEVELOPER,
  PRE_AUTHORIZATION_ENDPOINT,
  SERVER
} from "../../../shared/config/configuration.js";
import { VcScopeAction } from "../../../shared/interfaces/scope-action.interface.js";
import { SUPPORTED_SIGNATURE_ALG } from "../../../shared/config/supported_alg.js";
import { BadRequestError, InternalServerError } from "../../../shared/classes/errors.js";
import { AuthzErrorCodes } from "../../../shared/constants/error_codes.constants.js";
import {
  VERIFIABLE_ATTESTATION_TYPE,
  VERIFIABLE_CREDENTIAL_TYPE
} from "../../../shared/constants/credential.constants.js";
import { URLSearchParams } from "url";

@singleton()
@autoInjectable()
export default class AuthRules {
  constructor(private logger: Logger, private authSchema: AuthSchema) { }

  keyResolver = getResolver();
  didResolver = new Resolver(this.keyResolver);

  /**
   * Generate the instance of a RP
   * @param issuer The issuer identifier
   * @returns An instance of a RP
   */
  buildRp = (
    issuer: string
  ): OpenIDReliyingParty => {
    const metadata = generateDefaultAuthorisationServerMetadata(issuer);
    metadata.grant_types_supported?.push(
      "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    );
    return new OpenIDReliyingParty(
      async () => this.generateClientMetadata(this.authSchema.client_metadata),
      metadata,
      this.didResolver
    );
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
    const uniqueType = Array.isArray(types) ? types.find((type) => {
      return (type !== VERIFIABLE_CREDENTIAL_TYPE && type !== VERIFIABLE_ATTESTATION_TYPE);
    }) : types;
    if (!uniqueType) {
      throw new BadRequestError(
        "Invalid VC type specificated", AuthzErrorCodes.INVALID_REQUEST
      );
    }
    const tmp = issuerUri.split("/");
    const issuerId = tmp[tmp.length - 1];
    const params = new URLSearchParams(Object.entries({
      credential_types: uniqueType,
      issuer: issuerId
    })).toString();
    const data = await fetch(`${SERVER.scope_action}?${params}`);
    return await data.json() as VcScopeAction;
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
    kid: string,
    subject: string,
    issuer: string,
    scope: string,
    type?: string
  ): Promise<string> => {
    const header = {
      alg: SUPPORTED_SIGNATURE_ALG,
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
   * Send a pre-authorize_code to receive user information if correct
   * @param code The code to send
   * @param pin The pin to send with the code
   * @returns undefined if the code is invalid. User ID and VC requested if correct
   */
  exchangePreAuthCode = async (
    issuerUri: string,
    code: string,
    pin?: string,
  ): Promise<PreAuthCodeData | undefined> => {
    try {
      let url = `${removeSlash(issuerUri)}${PRE_AUTHORIZATION_ENDPOINT}/${code}`;
      if (pin) {
        const params = new URLSearchParams(Object.entries({ pin })).toString();
        url = url + `?${params}`;
      }
      const fetchResponse = await fetch(url);
      if (!fetchResponse.ok) {
        if (DEVELOPER.allow_empty_vc
          && DEVELOPER.pre_authorize_client
          && DEVELOPER.pre_authorize_vc_type) {
          return {
            client_id: DEVELOPER.pre_authorize_client,
            vc_type: DEVELOPER.pre_authorize_vc_type
          }
        }
        if (fetchResponse.status === 404) {
          return undefined;
        }
        throw new InternalServerError(
          "Can't exchanged pre-authorization_code",
          "server_error"
        )
      }
      return await fetchResponse.json() as PreAuthCodeData;
    } catch (e: any) {
      if (DEVELOPER.allow_empty_vc
        && DEVELOPER.pre_authorize_client
        && DEVELOPER.pre_authorize_vc_type) {
        return {
          client_id: DEVELOPER.pre_authorize_client,
          vc_type: DEVELOPER.pre_authorize_vc_type
        }
      }
      throw e;
    }
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
    description: string
  ) => {
    return {
      status: 302, location: this.buildRedirectResponse(
        uri,
        new URLSearchParams(Object.entries({
          code: code,
          error_description: description
        })).toString()
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
    expectedScope: string
  ): Promise<VerifiedBaseAuthzRequest> {
    const verifiedAuthz = await rp.verifyBaseAuthzRequest(
      authRequest,
      {
        scopeVerifyCallback: async (scope) => {
          if (scope === expectedScope) {
            return { valid: true };
          } else {
            return { valid: false, error: "Invalid scope specified" };
          }
        }
      }
    );
    if (!verifiedAuthz.validatedClientMetadata.responseTypesSupported.includes("id_token")) {
      throw new InvalidRequest(`Client does not support response_type "id_token"`);
    }
    if (!verifiedAuthz.validatedClientMetadata.idTokenAlg.includes(SUPPORTED_SIGNATURE_ALG)) {
      throw new InvalidRequest(`Client does not support id_token signing algorithm "ES256"`);
    }
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
    const redirect_uri = hasParams ? redirectUri : redirectUri?.endsWith("/") ? redirectUri : `${redirectUri}/`;
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
    // If validation fails, throw an error with details
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

}
