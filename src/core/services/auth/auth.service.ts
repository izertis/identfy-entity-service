import { autoInjectable, singleton } from "tsyringe";
import {
  JWK,
  JWTPayload,
  KeyLike,
  SignJWT,
  calculateJwkThumbprint
} from "jose";
import { verifyChallenge } from "pkce-challenge";
import {
  AccessDenied,
  AuthzRequest,
  DIFPresentationDefinition,
  IdTokenRequest,
  InvalidClient,
  InvalidRequest,
  OPENID_CREDENTIAL_AUTHZ_DETAILS_TYPE,
  OpenIDReliyingParty,
  OpenIdError,
  TokenRequest,
  VerifiedBaseAuthzRequest,
  VpTokenRequest,
  decodeToken,
  verifyJwtWithExpAndAudience
} from "openid-lib";
import Logger from "../../../shared/classes/logger.js";
import AuthRules from "./auth.rules.js";
import {
  BadRequestError,
  HttpError,
  InternalServerError
} from "../../../shared/classes/errors.js";
import {
  VcScopeAction, VpScopeAction
} from "../../../shared/interfaces/scope-action.interface.js";
import { AUTHORIZATION } from "../../../shared/config/configuration.js";
import {
  SUPPORTED_SIGNATURE_ALG
} from "../../../shared/config/supported_alg.js";
import { errorToString } from "../../../shared/utils/api.utils.js";
import NonceService from "../nonce/nonce.service.js";
import {
  AuthnErrorCodes,
  AuthzErrorCodes
} from "../../../shared/constants/error_codes.constants.js";
import {
  NonceAuthState,
  NoncePostState,
  ResponseTypeOpcode
} from "../../../shared/interfaces/nonce.interface.js";
import { IAuthzRequest } from "../../../shared/interfaces/auth.interface.js";
import { areSameDid } from "../../../shared/utils/did.utils.js";
import { JwtPayload } from "jsonwebtoken";

@singleton()
@autoInjectable()
export default class AuthService {
  constructor(
    private logger: Logger,
    private rules: AuthRules,
    private nonceService: NonceService,
  ) { }

  /**
   * Retrieves the static OIDC Configuration object.
   *
   * @param issuerUri - The issuer URI to use for constructing the configuration URLs.
   * @returns The OIDC Configuration object with updated URLs.
   */
  getConfiguration(issuerUri: string): any {
    return { status: 200, ...this.rules.getIssuerMetadata(issuerUri) };
  }

  /**
   * Authorization request.
   *
   * @param issuerUri - The issuer URI to use for constructing the URLs.
   * @param privateKeyStr - The private key string in JWK format.
   * @param publicKeyStr - The public key string in JWK format.
   * @param authRequest - The authorization request object.
   * @returns An object containing the status code and the location for redirection.
   */
  async authorize(
    issuerUri: string,
    privateKeyStr: string,
    publicKeyStr: string,
    authRequest: IAuthzRequest,
  ) {
    try {
      if (typeof authRequest.authorization_details === "string") {
        authRequest.authorization_details =
          await this.rules.validateAuthorizationDetails(
            authRequest.authorization_details
          );
      }
      this.logger.log("Authz details validated");
      if (typeof authRequest.client_metadata === "string") {
        authRequest.client_metadata =
          await this.rules.validateClientMetadata(authRequest.client_metadata);
      }
      this.logger.log("Client metadata validated");
      const rp = this.rules.buildRp(issuerUri);
      this.logger.log("Openid RP instance created");
      const verifiedAuthz = await this.rules.verifyBaseAuthzRequest(
        rp,
        authRequest as AuthzRequest,
      );
      let vcTypesFromAuthzDetails: string[] | undefined;
      if (verifiedAuthz.authzRequest.authorization_details) {
        // VC Issuance
        for (const details of verifiedAuthz.authzRequest.authorization_details) {
          if (details.type === OPENID_CREDENTIAL_AUTHZ_DETAILS_TYPE) {
            vcTypesFromAuthzDetails = details.types!;
            break;
          }
        }
      }
      this.logger.log("Authz details analyzed");
      if (vcTypesFromAuthzDetails) {
        // VC Issuance
        return await this.authorizeForIssuance(
          issuerUri,
          privateKeyStr,
          publicKeyStr,
          rp,
          vcTypesFromAuthzDetails,
          verifiedAuthz
        );
      }
      // VP Verification
      return await this.authorizeForVerification(
        issuerUri,
        privateKeyStr,
        publicKeyStr,
        rp,
        verifiedAuthz
      );
    } catch (error: any) {
      if (error instanceof OpenIdError || error instanceof HttpError) {
        return this.rules.generateLocationErrorResponse(
          authRequest.redirect_uri,
          error.code,
          error.message,
          authRequest.state
        );
      }
      return this.rules.generateLocationErrorResponse(
        authRequest.redirect_uri,
        "server_error",
        error.message,
        authRequest.state
      );
    }
  }


  private async getKeyMaterial(
    privateKeyStr: string,
    publicKeyStr: string,
  ) {
    const parsedKeys = this.rules
      .parseKeysJwk(privateKeyStr, publicKeyStr)
      .catch((error) => {
        throw new BadRequestError(errorToString(error), "invalid_request");
      });
    const privateKey = (await parsedKeys).keyLike.privateKey;
    const publicKeyJwk = (await parsedKeys).jwk.publicKey;
    const pubKeyThumbprint = await calculateJwkThumbprint(publicKeyJwk);
    return {
      privateKey,
      publicKeyJwk,
      pubKeyThumbprint
    }
  }

  private async authorizeForIssuance(
    issuerUri: string,
    privateKeyStr: string,
    publicKeyStr: string,
    rp: OpenIDReliyingParty,
    vcTypesFromAuthzDetails: string[],
    verifiedAuthz: VerifiedBaseAuthzRequest
  ) {
    let optionalParams: Record<string, any> = {};
    const {
      privateKey,
      publicKeyJwk,
      pubKeyThumbprint
    } = await this.getKeyMaterial(
      privateKeyStr,
      publicKeyStr
    );
    const scopeAction = await this.rules.getIssuanceInfo(
      issuerUri,
      vcTypesFromAuthzDetails
    );
    if (!scopeAction) {
      throw new InvalidRequest(
        "Invalid credentials requested"
      );
    }
    this.logger.log("Authz request verified");
    if (!verifiedAuthz.serviceWalletJWK) {
      if (!verifiedAuthz.authzRequest.code_challenge ||
        !verifiedAuthz.authzRequest.code_challenge_method) {
        throw new BadRequestError(
          "A code_challenge is required",
          AuthzErrorCodes.INVALID_REQUEST
        );
      }
      if (verifiedAuthz.authzRequest.code_challenge_method !== "S256") {
        throw new BadRequestError(
          "Unssuported code_challenge_method",
          AuthzErrorCodes.INVALID_REQUEST
        );
      }
      optionalParams = {
        codeChallenge: verifiedAuthz.authzRequest.code_challenge,
      }
    } else {
      optionalParams = {
        serviceWalletJwk: verifiedAuthz.serviceWalletJWK
      }
    }
    optionalParams = {
      ...optionalParams,
      type: scopeAction.credential_types,
      clientState: verifiedAuthz.authzRequest.state
    }
    const aud = verifiedAuthz.authzRequest.client_id;
    const request = await this.processScopeAction(
      scopeAction,
      issuerUri,
      rp,
      verifiedAuthz,
      privateKey,
      publicKeyJwk,
      pubKeyThumbprint,
      aud
    );
    await this.nonceService.registerNonceForAuth(
      aud,
      request.requestParams.nonce!,
      ResponseTypeOpcode.ISSUANCE,
      verifiedAuthz.authzRequest.redirect_uri,
      verifiedAuthz.authzRequest.scope,
      optionalParams
    );
    this.logger.log("Nonce for Authz registered");
    return { status: 302, location: request.toUri() }
  }

  private async authorizeForVerification(
    issuerUri: string,
    privateKeyStr: string,
    publicKeyStr: string,
    rp: OpenIDReliyingParty,
    verifiedAuthz: VerifiedBaseAuthzRequest
  ) {
    this.logger.log("Authorize - Verification flow");
    const {
      privateKey,
      publicKeyJwk,
      pubKeyThumbprint
    } = await this.getKeyMaterial(
      privateKeyStr,
      publicKeyStr
    );
    const scopeAction = await this.rules.getVerificationInfo(
      issuerUri,
      verifiedAuthz.authzRequest.scope
    );
    if (!scopeAction) {
      throw new InvalidRequest(
        "Invalid scope specified"
      );
    }
    const aud = verifiedAuthz.authzRequest.client_id;
    const request = await this.processScopeAction(
      scopeAction,
      issuerUri,
      rp,
      verifiedAuthz,
      privateKey,
      publicKeyJwk,
      pubKeyThumbprint,
      aud
    );
    await this.nonceService.registerNonceForAuth(
      aud,
      request.requestParams.nonce!,
      ResponseTypeOpcode.VERIFICATION,
      verifiedAuthz.authzRequest.redirect_uri,
      verifiedAuthz.authzRequest.scope,
      {
        clientState: verifiedAuthz.authzRequest.state
      }
    );
    this.logger.log("Nonce for Authz registered");
    return { status: 302, location: request.toUri() }
  }

  private async processScopeAction(
    scopeAction: VcScopeAction | VpScopeAction,
    issuerUri: string,
    rp: OpenIDReliyingParty,
    verifiedAuthz: VerifiedBaseAuthzRequest,
    privateKey: KeyLike | Uint8Array,
    publicKeyJwk: JWK,
    pubKeyThumbprint: string,
    aud: string
  ): Promise<IdTokenRequest | VpTokenRequest> {
    let request: IdTokenRequest | VpTokenRequest;
    if (scopeAction.response_type === "vp_token") {
      request = await this.requestVpToken(
        issuerUri,
        rp,
        verifiedAuthz,
        privateKey,
        publicKeyJwk,
        pubKeyThumbprint,
        scopeAction.presentation_definition!,
        aud
      );
      this.logger.log("VP Token Request created");
    } else if (scopeAction.response_type === "id_token") {
      request = await this.requestIdToken(
        issuerUri,
        rp,
        verifiedAuthz,
        privateKey,
        publicKeyJwk,
        pubKeyThumbprint,
        aud
      )
      this.logger.log("ID Token Request created");
    } else {
      this.logger.error(
        `Unssuported response_type specified: ${scopeAction.response_type}`
      );
      throw new InternalServerError(
        "Unssuported response_type specified", "internal_error"
      );
    }
    return request;
  }

  private async requestIdToken(
    issuerUri: string,
    rp: OpenIDReliyingParty,
    verifiedAuthz: VerifiedBaseAuthzRequest,
    privateKey: KeyLike | Uint8Array,
    publicKeyJwk: JWK,
    pubKeyThumbprint: string,
    aud: string
  ): Promise<IdTokenRequest> {
    // We only support one signing algorithm
    const authzEndpoint =
      verifiedAuthz.validatedClientMetadata.authorizationEndpoint.endsWith(':') ?
        verifiedAuthz.validatedClientMetadata.authorizationEndpoint + "//" :
        verifiedAuthz.validatedClientMetadata.authorizationEndpoint;
    return await rp.createIdTokenRequest(
      authzEndpoint,
      aud,
      issuerUri.concat(AUTHORIZATION.direct_post_endpoint),
      this.rules.generateJwt(
        privateKey,
        publicKeyJwk,
        pubKeyThumbprint
      ),
    );
  }

  private async requestVpToken(
    issuerUri: string,
    rp: OpenIDReliyingParty,
    verifiedAuthz: VerifiedBaseAuthzRequest,
    privateKey: KeyLike | Uint8Array,
    publicKeyJwk: JWK,
    pubKeyThumbprint: string,
    definition: DIFPresentationDefinition,
    aud: string
  ): Promise<VpTokenRequest> {
    const authzEndpoint =
      verifiedAuthz.validatedClientMetadata.authorizationEndpoint.endsWith(':') ?
        verifiedAuthz.validatedClientMetadata.authorizationEndpoint + "//" :
        verifiedAuthz.validatedClientMetadata.authorizationEndpoint;
    return await rp.createVpTokenRequest(
      authzEndpoint,
      aud,
      issuerUri.concat(AUTHORIZATION.direct_post_endpoint),
      this.rules.generateJwt(
        privateKey,
        publicKeyJwk,
        pubKeyThumbprint
      ),
      {
        presentation_definition: definition
      }
    );
  }

  /**
   * Processes a direct post response containing the ID token.
   *
   * @param entityUri - The URI of the issuer.
   * @param privateKeyStr - JWK Private Key in string format.
   * @param idToken - The ID token sent by the holder.
   * @param vpToken - The VP token sent by the holder.
   * @param presentationSubmission - The VP submission sent with a VP Token.
   * @returns An object containing the status code and the location for redirection.
   */
  async directPost(
    entityUri: string,
    privateKeyStr: string,
    idToken?: string,
    vpToken?: string,
    presentationSubmission?: string,
  ) {
    const token = idToken ?? vpToken;
    if (!token) {
      throw new HttpError(
        400,
        AuthzErrorCodes.INVALID_REQUEST,
        "Neither id_token nor vp_token was specified"
      );
    }
    const tokenType = idToken ? TokenType.ID : TokenType.VP;
    const parsedKeys = await this.rules
      .parseKeysJwk(privateKeyStr)
      .catch((error) => {
        throw new BadRequestError(errorToString(error), "invalid_request");
      });
    const privateKeyJwk = parsedKeys.jwk.privateKey;
    const privateKey = parsedKeys.keyLike.privateKey;

    const { payload } = decodeToken(token);
    const jwtPayload = payload as JWTPayload;
    if (!jwtPayload.nonce) {
      throw new BadRequestError(
        AuthzErrorCodes.INVALID_REQUEST,
        `${tokenType} must contain a nonce parameter`
      );
    }

    this.logger.log("Get and verify the Nonce State");
    const nonceResponse = await this.nonceService.getNonce(jwtPayload.nonce as string);
    if (!nonceResponse) {
      throw new BadRequestError(
        AuthzErrorCodes.INVALID_REQUEST,
        `Invalid nonce specified in ${tokenType}`
      );
    }
    let nonceState: NonceAuthState;
    try {
      nonceState = NonceService.verifyAuthNonceState(nonceResponse.state!);
    } catch (error: any) {
      throw new BadRequestError(
        AuthzErrorCodes.INVALID_REQUEST,
        "The nonce specified has already been used"
      );
    }

    try {
      const rp = this.rules.buildRp(entityUri);

      const scopeAction = await this.rules.getScopeAction(
        entityUri,
        nonceState);

      if (scopeAction.response_type != tokenType) {
        throw new InvalidRequest(`Token type not expected: ${scopeAction.response_type} - ${tokenType}`);
      }

      const { holderDid, claimsData } = await this.rules.verifyToken(
        rp,
        token,
        tokenType,
        nonceState,
        nonceResponse,
        scopeAction.presentation_definition,
        presentationSubmission
      );

      if (tokenType === TokenType.VP) {
        const externalVerification =
          await this.rules.verifyOnExternalData(
            true,
            entityUri,
            (payload as JwtPayload).state,
            holderDid,
            claimsData
          )

        if (!externalVerification.verified) {
          throw new AccessDenied(
            "The provided data in the VCs did not pass the external verification"
          );
        }
      }

      if (nonceState.opcode === ResponseTypeOpcode.VERIFICATION) {
        await this.nonceService.deleteNonce(
          nonceResponse.nonce
        );
      } else {
        await this.nonceService.updateNonceForPostState(
          nonceResponse.nonce,
          nonceState.scope,
          holderDid,
          nonceState.code_challenge,
          nonceState.serviceJwk,
        );
      }

      if (isRedirectUriKnown(nonceState)) {
        const authzCode = await this.rules.generateAuthzCode(
          nonceResponse.nonce,
          privateKey,
          privateKeyJwk.alg || SUPPORTED_SIGNATURE_ALG,
          privateKeyJwk.kid || await calculateJwkThumbprint(privateKeyJwk),
          holderDid,
          entityUri,
          nonceState.scope,
          nonceState.type
        );
        const authzResponse = rp.createAuthzResponse(
          nonceState.redirect_uri,
          authzCode,
          nonceState.clientState
        );
        return { status: 302, location: authzResponse.toUri() }
      } else {
        return { status: 200 };
      }

    } catch (error: any) {
      // not need to await
      this.rules.verifyOnExternalData(
        false,
        entityUri,
        (payload as JwtPayload).state
      )

      if (isRedirectUriKnown(nonceState)) {
        if (error instanceof OpenIdError || error instanceof HttpError) {
          return this.rules.generateLocationErrorResponse(
            nonceState.redirect_uri,
            error.code,
            error.message,
            nonceState.clientState
          );
        }
        return this.rules.generateLocationErrorResponse(
          nonceState.redirect_uri,
          "server_error",
          error.message,
          nonceState.clientState
        );
      } else {
        if (error instanceof OpenIdError) {
          throw new HttpError(
            error.recomiendedHttpStatus!,
            error.code,
            error.message
          );
        }
        throw error;
      }
    }
  }

  /**
   * Grants an access token based on the provided parameters.
   *
   * @param issuerUri - The issuer URI.
   * @param privateKeyStr - The private key JWK.
   * @param publicKeyStr - The public key JWK.
   * @param tokenRequest - The request sent by the client.
   * @returns An object containing the status code and the access token information.
   * @throws HttpError if there are issues with the data provided with the client.
   */
  async grantAccessToken(
    issuerUri: string,
    privateKeyStr: string,
    publicKeyStr: string,
    tokenRequest: TokenRequest,
  ) {
    try {
      let finalClientId = tokenRequest.client_id;
      let pinCode: string | undefined;
      const parsedKeys = this.rules
        .parseKeysJwk(privateKeyStr, publicKeyStr)
        .catch((error) => {
          throw new HttpError(
            AuthnErrorCodes.INVALID_REQUEST.httpStatus,
            AuthnErrorCodes.INVALID_REQUEST.code,
            errorToString(error),
          );
        });
      const privateKey = (await parsedKeys).keyLike.privateKey;
      const publicKeyJwk = (await parsedKeys).jwk.publicKey;
      const pubKeyThumbprint = await calculateJwkThumbprint(publicKeyJwk);
      const rp = this.rules.buildRp(issuerUri);
      let nonceState: NoncePostState;
      let nonceInCode: string;
      let vcType: string;
      let isPreAuth = false;
      const tokenResponse = await rp.generateAccessToken(
        tokenRequest,
        false,
        // Sign Callback
        async (payload, _supportedSignAlg) => {
          const header = {
            alg: publicKeyJwk.alg || SUPPORTED_SIGNATURE_ALG,
            kid: publicKeyJwk.kid || pubKeyThumbprint,
          };
          const data = { ...payload, isPreAuth } as Record<string, any>;
          if (nonceState && nonceState.serviceJwk) {
            data.serviceWalletDid = nonceState.clientDid;
          } else if (pinCode) {
            data.pin = pinCode;
          }
          if (vcType) {
            data.vcType = vcType;
          }
          return await new SignJWT(data)
            .setProtectedHeader(header)
            .sign(privateKey);
        },
        issuerUri,
        {
          preAuthorizeCodeCallback: async (_clientId, preCode, pin) => {
            isPreAuth = true;
            finalClientId = preCode;
            pinCode = pin;
            return { client_id: preCode };
          },
          authorizeCodeCallback: async (clientId, code) => {
            try {
              verifyJwtWithExpAndAudience(code, publicKeyJwk, issuerUri);
            } catch (error: any) {
              return {
                valid: false,
                error: error.message
              }
            }
            const { payload } = decodeToken(code);
            const jwtPayload = payload as JWTPayload;
            if (!jwtPayload.nonce || !jwtPayload.type) {
              return { valid: false };
            }
            nonceInCode = jwtPayload.nonce as string;
            const nonceResponse = await this.nonceService.getNonce(
              jwtPayload.nonce as string
            );
            if (!nonceResponse) {
              return {
                valid: false,
                error: `No pending auth request for ${clientId}`
              };
            }
            // En este punto no estoy validando una firma, solo que hablo con el mismo DID
            // por ese motivo no utilizamos los derivation path
            if (!areSameDid(nonceResponse.did, clientId)) {
              return {
                valid: false,
                error: "The code received is not related to the client"
              };
            }
            try {
              nonceState = NonceService.verifyPostNonceState(nonceResponse.state!);
              vcType = jwtPayload.type as string;
              return { valid: true };
            } catch (_error) {
              return {
                valid: false,
                error: `An authz code has not been generated yet or it has been used already`
              };
            }
          },
          codeVerifierCallback: async (_clientId, codeVerifier) => {
            if (!codeVerifier) {
              return { valid: false, error: "A code_verifier is required" };
            }
            const result = await verifyChallenge(codeVerifier, nonceState.codeChallenge!);
            if (!result) {
              return { valid: false, error: `The "code_verifier" provided is invalid` };
            } else {
              return { valid: true }
            }
          },
          retrieveClientAssertionPublicKeys: async (client_id: string) => {
            if (!nonceState.serviceJwk) {
              throw new InvalidClient(
                `Client ${client_id} has not been authorize as a Service Wallet`
              );
            }
            finalClientId = nonceState.clientDid;
            return nonceState.serviceJwk;
          }
        }
      );
      await this.nonceService.registerAccessTokenNonce(
        finalClientId,
        tokenResponse.c_nonce,
        tokenResponse.c_nonce
      );
      if (!isPreAuth) {
        await this.nonceService.deleteNonce(nonceInCode!);
      }
      return {
        status: 200,
        ...tokenResponse
      };
    } catch (error: any) {
      if (error instanceof OpenIdError) {
        throw new HttpError(
          error.recomiendedHttpStatus!,
          error.code,
          error.message
        );
      }
      throw error;
    }
  }

  /**
   * Create a VP Token Request for Presentation Offer.
   *
   * @param issuerUri - The issuer URI.
   * @param privateKeyStr - The private key JWK.
   * @param publicKeyStr - The public key JWK.
   * @param scope - Information of VP scope action and presentation definition.
   * @param state - Optional state to identify user
   * @returns An object containing the status code and the jwt with vp_token_request.
   * @throws HttpError if there are issues with the data provided with the client.
   */
  async createPresentationOffer(
    issuerUri: string,
    privateKeyStr: string,
    publicKeyStr: string,
    scope: VpScopeAction,
    state?: string,
  ): Promise<VpTokenRequest> {
    const rp = this.rules.buildRp(issuerUri);
    this.logger.log("Openid RP instance created");
    const {
      privateKey,
      publicKeyJwk,
      pubKeyThumbprint
    } = await this.getKeyMaterial(
      privateKeyStr,
      publicKeyStr
    );

    if (!scope) {
      throw new InvalidRequest(
        "Invalid scope specified"
      );
    }

    this.logger.log("Before creating VP token");
    const vpRequest: VpTokenRequest = await rp.createVpTokenRequest(
      "",
      "https://self-issued.me/v2",
      issuerUri.concat(AUTHORIZATION.direct_post_endpoint),
      this.rules.generateJwt(
        privateKey,
        publicKeyJwk,
        pubKeyThumbprint
      ),
      { // EBSI set the scope to openid, although it could be another one in the Authz request
        state: state,
        scope: scope.scope,
        presentation_definition: scope.presentation_definition,
      }
    );
    this.logger.log("Created VP token");
    //  Register nonce after create it into VpTokenRequest call
    await this.nonceService.registerNonceForAuth(
      "null",
      vpRequest.requestParams.nonce!,
      ResponseTypeOpcode.VERIFICATION,
      "null",
      scope.scope
    );
    this.logger.log("Nonce for Authz registered");
    return vpRequest;
  }
}

export enum TokenType {
  VP = 'vp_token',
  ID = 'id_token'
}

function isRedirectUriKnown(nonceState: NonceAuthState) {
  return nonceState.redirect_uri && nonceState.redirect_uri !== "null";
}
