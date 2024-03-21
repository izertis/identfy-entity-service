import { autoInjectable, singleton } from "tsyringe";
import { JWTPayload, SignJWT, calculateJwkThumbprint } from "jose";
import { verifyChallenge } from "pkce-challenge";
import {
  AuthzRequest,
  InvalidRequest,
  OPENID_CREDENTIAL_AUTHZ_DETAILS_TYPE,
  OpenIdError,
  TokenRequest,
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
  VcScopeAction
} from "../../../shared/interfaces/scope-action.interface.js";
import { AUTHORIZATION } from "../../../shared/config/configuration.js";
import {
  SUPPORTED_SIGNATURE_ALG
} from "../../../shared/config/supported_alg.js";
import { errorToString, removeSlash } from "../../../shared/utils/api.utils.js";
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
import { IAuthzRequest } from "shared/interfaces/auth.interface.js";

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
    // Remove "/" if it comes set in the parameter
    issuerUri = removeSlash(issuerUri);
    // Destructure the AUTHORIZATION object
    let {
      issuer,
      authorization_endpoint,
      token_endpoint,
      jwks_uri,
      direct_post_endpoint,
      ...rest
    } = AUTHORIZATION;
    // Update the URLs by appending the issuer URI
    issuer = issuerUri.concat(issuer);
    authorization_endpoint = issuerUri.concat(authorization_endpoint);
    token_endpoint = issuerUri.concat(token_endpoint);
    jwks_uri = issuerUri.concat(jwks_uri);
    direct_post_endpoint = issuerUri.concat(direct_post_endpoint);
    // Construct the response object with updated URLs
    const response = {
      issuer,
      authorization_endpoint,
      token_endpoint,
      jwks_uri,
      direct_post_endpoint,
      ...rest,
    };
    // Return the response object with a status of 200
    return { status: 200, ...response };
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
    // TODO: Should we check redirect_uri or its format?
    try {
      if (typeof authRequest.authorization_details === "string") {
        authRequest.authorization_details =
          await this.rules.validateAuthorizationDetails(authRequest.authorization_details);
      }
      this.logger.log("Authz details validated");
      if (typeof authRequest.client_metadata === "string") {
        authRequest.client_metadata =
          await this.rules.validateClientMetadata(authRequest.client_metadata);
      }
      this.logger.log("Client metadata validated");
      const parsedKeys = this.rules
        .parseKeysJwk(privateKeyStr, publicKeyStr)
        .catch((error) => {
          throw new BadRequestError(errorToString(error), "invalid_request");
        });
      const privateKey = (await parsedKeys).keyLike.privateKey;
      const publicKeyJwk = (await parsedKeys).jwk.publicKey;
      const pubKeyThumbprint = await calculateJwkThumbprint(publicKeyJwk);
      const rp = this.rules.buildRp(issuerUri);
      this.logger.log("Openid RP instance created");
      let scopeAction: VcScopeAction | undefined;
      if (authRequest.authorization_details) {
        // VC Issuance
        // TODO: Modify lib
        for (const details of authRequest.authorization_details) {
          if (details.type === OPENID_CREDENTIAL_AUTHZ_DETAILS_TYPE) {
            scopeAction = await this.rules.getIssuanceInfo(issuerUri, details.types!);
            break;
          }
        }
      } else {
        // VP
        // TODO: VP ARE PENDING
        throw new InvalidRequest(
          "No authorization details were found in the request received"
        );
      }
      this.logger.log("Authz details analyzed");
      if (!scopeAction) {
        throw new InvalidRequest(
          "Invalid credentials requested"
        );
      }
      if (scopeAction.response_type === "vp_token") {
        throw new BadRequestError(
          "VP Token response_type is not supported", "invalid_request"
        );
      }
      const verifiedAuthz = await this.rules.verifyBaseAuthzRequest(
        rp,
        authRequest as AuthzRequest,
        scopeAction.scope
      );
      this.logger.log("Authz request verified");
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
      // We only support one signing algorithm
      const idTokenRequest = await rp.createIdTokenRequest(
        verifiedAuthz.validatedClientMetadata.authorizationEndpoint,
        verifiedAuthz.authzRequest.client_id,
        issuerUri.concat(AUTHORIZATION.direct_post_endpoint),
        async (payload, _algs) => {
          const header = {
            typ: "JWT",
            alg: SUPPORTED_SIGNATURE_ALG,
            kid: publicKeyJwk.kid || pubKeyThumbprint,
          };
          return await new SignJWT(payload)
            .setProtectedHeader(header)
            .setIssuedAt()
            .sign(privateKey);
        },
        {
          scope: scopeAction!.scope
        }
      );
      this.logger.log("ID Token Request created");
      await this.nonceService.registerNonceForAuth(
        authRequest.client_id,
        idTokenRequest.requestParams.nonce!,
        ResponseTypeOpcode.ISSUANCE,
        authRequest.redirect_uri,
        authRequest.scope,
        {
          codeChallenge: authRequest.code_challenge,
          type: scopeAction.credential_types,
          clientState: authRequest.state
        }
      );
      this.logger.log("Nonce for Authz registered");
      return { status: 302, location: idTokenRequest.toUri() }
    } catch (error: any) {
      if (error instanceof OpenIdError || error instanceof HttpError) {
        return this.rules.generateLocationErrorResponse(
          authRequest.redirect_uri,
          error.code,
          error.message
        );
      }
      return this.rules.generateLocationErrorResponse(
        authRequest.redirect_uri,
        "server_error",
        error.message
      );
    }
  }

  /**
   * Processes a direct post response containing the ID token.
   *
   * @param issuerUri - The URI of the issuer.
   * @param privateKeyStr - JWK Private Key in string format.
   * @param idToken - The ID token sent by the holder.
   * @param vp_token - The VP token sent by the holder.
   * @param presentation_submission - The VP submission sent with a VP Token.
   * @returns An object containing the status code and the location for redirection.
   */
  async directPost(
    issuerUri: string,
    privateKeyStr: string,
    idToken?: string,
    vp_token?: string,
    presentation_submission?: string,
  ) {
    const parsedKeys = await this.rules
      .parseKeysJwk(privateKeyStr)
      .catch((error) => {
        throw new BadRequestError(errorToString(error), "invalid_request");
      });
    const privateKeyJwk = parsedKeys.jwk.privateKey;
    const privateKey = parsedKeys.keyLike.privateKey;
    const token = idToken ?? vp_token;
    const isVpToken = !idToken;
    if (isVpToken) {
      throw new InternalServerError(
        "VP Tokens are not suppored",
        AuthzErrorCodes.INVALID_REQUEST,
      );
    }
    if (!token) {
      throw new HttpError(
        400,
        AuthzErrorCodes.INVALID_REQUEST,
        "Neither id_token nor vp_token was specified"
      );
    }
    const { payload } = decodeToken(token);
    const jwtPayload = payload as JWTPayload;
    if (!jwtPayload.nonce) {
      throw new HttpError(
        400,
        AuthzErrorCodes.INVALID_REQUEST,
        "ID Token must contain a nonce parameter"
      );
    }
    const nonceResponse = await this.nonceService.getNonce(jwtPayload.nonce as string);
    if (!nonceResponse) {
      throw new HttpError(
        400,
        AuthzErrorCodes.INVALID_REQUEST,
        "Invalid nonce specified in ID Token"
      );
    }
    let nonceState: NonceAuthState;
    try {
      nonceState = NonceService.verifyAuthNonceState(nonceResponse.state!);
    } catch (error: any) {
      throw new HttpError(
        400,
        AuthzErrorCodes.INVALID_REQUEST,
        "The nonce specified has already been used"
      );
    }
    try {
      if (nonceState.opcode !== ResponseTypeOpcode.ISSUANCE) {
        throw new InternalServerError(
          "Unexpected vp_token response type",
          AuthzErrorCodes.INVALID_REQUEST
        );
      }
      const rp = this.rules.buildRp(issuerUri);
      const verifiedIdTokenResponse = await rp.verifyIdTokenResponse(
        {
          id_token: token,
        },
        async (_header, payload, didDocument) => {
          if (payload.scope && payload.scope !== nonceState.scope) {
            return { valid: false, error: "The scope specified is invalid" };
          }
          if (nonceResponse.did !== didDocument.id) {
            return {
              valid: false,
              error: "The nonce specified and the issuer of the token are not correlated"
            };
          }
          return { valid: true };
        }
      );

      const authzCode = await this.rules.generateAuthzCode(
        nonceResponse.nonce,
        privateKey,
        privateKeyJwk.kid || await calculateJwkThumbprint(privateKeyJwk),
        verifiedIdTokenResponse.didDocument.id,
        issuerUri,
        nonceState.scope,
        nonceState.type
      );
      const authzResponse = rp.createAuthzResponse(
        nonceState.redirect_uri,
        authzCode,
        nonceState.clientState
      );
      await this.nonceService.updateNonceForPostState(
        nonceResponse!.nonce,
        nonceState!.scope,
        nonceState!.code_challenge
      );
      return { status: 302, location: authzResponse.toUri() }
    } catch (error: any) {
      if (error instanceof OpenIdError || error instanceof HttpError) {
        return this.rules.generateLocationErrorResponse(
          nonceState.redirect_uri,
          error.code,
          error.message
        );
      }
      return this.rules.generateLocationErrorResponse(
        nonceState.redirect_uri,
        "server_error",
        error.message
      );
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
      // TODO: OPENID-LIB Pass code to codeVerifier callback
      const tokenResponse = await rp.generateAccessToken(
        tokenRequest,
        false,
        // Sign Callback
        async (payload, _supportedSignAlg) => {
          const header = {
            alg: SUPPORTED_SIGNATURE_ALG,
            kid: publicKeyJwk.kid || pubKeyThumbprint,
          };
          const data = { ...payload, isPreAuth };
          if (pinCode) {
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
            // TODO: CHECK CODE VALIDITY WITH THIRD ENTITY
            isPreAuth = true;
            finalClientId = preCode;
            pinCode = pin;
            return { client_id: preCode };
            // const exchangeData = await this.rules.exchangePreAuthCode(
            //   issuerUri,
            //   preCode,
            //   pin
            // );
            // if (!exchangeData) {
            //   return { error: "Invalid pre-authorization_code" };
            // }
            // if (clientId && exchangeData.client_id !== clientId) {
            //   return {
            //     error: "Pre-authorization_code was emitted for another client"
            //   };
            // }
            // vcType = exchangeData.vc_type;
            // isPreAuth = true;
            // finalClientId = exchangeData.client_id;
            // return { client_id: exchangeData.client_id };
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
            if (nonceResponse.did !== clientId) {
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
}
