import {autoInjectable, singleton} from 'tsyringe';
import {JWTPayload} from 'jose';
import {
  AccessDenied,
  AuthorizationResponse,
  AuthzRequest,
  IdTokenRequest,
  InvalidRequest,
  OPENID_CREDENTIAL_AUTHZ_DETAILS_TYPE,
  OpenIDReliyingParty,
  OpenIdError,
  RequestPurpose,
  TokenRequest,
  VerifiedBaseAuthzRequest,
  VpTokenRequest,
  decodeToken,
} from 'openid-lib';
import Logger from '../../../shared/classes/logger.js';
import AuthRules from './auth.rules.js';
import {
  BadRequestError,
  HttpError,
  InternalServerError,
} from '../../../shared/classes/error/httperrors.js';
import {
  VcScopeAction,
  VpScopeAction,
} from '../../../shared/interfaces/scope-action.interface.js';
import {AUTHORIZATION} from '../../../shared/config/configuration.js';
import {
  AuthzErrorCodes
} from '../../../shared/constants/error_codes.constants.js';
import {IAuthzRequest} from '../../../shared/interfaces/auth.interface.js';
import {
  IdentityFactory
} from '../../../shared/utils/identity/identity-factory.js';
import {JwtPayload} from 'jsonwebtoken';
import {getIssuanceInfo, getVerificationInfo} from '../request_info/index.js';
import {keysBackend} from '../../../shared/utils/functions/auth.utils.js';
import {
  SignatureProvider
} from '../../../shared/classes/signature_provider/index.js';
import {PublicKeyFormat} from '../../../shared/types/keys.type.js';

@singleton()
@autoInjectable()
export default class AuthService {
  constructor(
    private logger: Logger,
    private rules: AuthRules,
  ) {}

  /**
   * Retrieves the static OIDC Configuration object.
   *
   * @param issuerUri - The issuer URI to use for constructing the configuration URLs.
   * @returns The OIDC Configuration object with updated URLs.
   */
  getConfiguration(issuerUri: string): any {
    return {
      status: 200,
      ...this.rules.getIssuerMetadata(issuerUri),
    };
  }

  /**
   * Authorization request.
   *
   * @param issuerUri - The issuer URI to use for constructing the URLs.
   * @param authRequest - The authorization request object.
   * @returns An object containing the status code and the location for redirection.
   */
  async authorize(
    issuerUri: string,
    authRequest: IAuthzRequest,
  ) {
    try {
      const rp = await this.rules.buildRp(issuerUri);
      this.logger.log('Openid RP instance created');
      const verifiedAuthz = await rp.verifyBaseAuthzRequest(
        authRequest as AuthzRequest,
      );
      let vcTypesFromAuthzDetails: string[] | undefined;
      if (verifiedAuthz.authzRequest.authorization_details) {
        // VC Issuance
        for (const details of verifiedAuthz.authzRequest
          .authorization_details) {
          if (details.type === OPENID_CREDENTIAL_AUTHZ_DETAILS_TYPE) {
            vcTypesFromAuthzDetails = details.types!;
            break;
          }
        }
      }
      this.logger.log('Authz details analyzed');
      if (vcTypesFromAuthzDetails) {
        // VC Issuance
        return await this.authorizeForIssuance(
          issuerUri,
          rp,
          vcTypesFromAuthzDetails,
          verifiedAuthz,
        );
      }
      // VP Verification
      return await this.authorizeForVerification(issuerUri, rp, verifiedAuthz);
    } catch (error: any) {
      if (error instanceof OpenIdError || error instanceof HttpError) {
        return this.rules.generateLocationErrorResponse(
          authRequest.redirect_uri,
          error.code,
          error.message,
          authRequest.state,
        );
      }
      return this.rules.generateLocationErrorResponse(
        authRequest.redirect_uri,
        'server_error',
        error.message,
        authRequest.state,
      );
    }
  }

  private async authorizeForIssuance(
    issuerUri: string,
    rp: OpenIDReliyingParty,
    vcTypesFromAuthzDetails: string[],
    verifiedAuthz: VerifiedBaseAuthzRequest,
  ) {
    const scopeAction = await getIssuanceInfo(
      issuerUri,
      vcTypesFromAuthzDetails,
    );
    if (!scopeAction) {
      throw new InvalidRequest('Invalid credentials requested');
    }
    this.logger.log('Authz request verified');
    if (!verifiedAuthz.serviceWalletJWK) {
      if (verifiedAuthz.authzRequest.code_challenge_method !== 'S256') {
        throw new BadRequestError(
          'Unssuported code_challenge_method',
          AuthzErrorCodes.INVALID_REQUEST,
        );
      }
    }

    const aud = this.getClientIdentity(verifiedAuthz.authzRequest.client_id);

    const request = await this.processScopeAction(
      scopeAction,
      issuerUri,
      rp,
      {
        type: 'Issuance',
        verifiedBaseAuthzRequest: verifiedAuthz,
      },
      aud,
    );

    this.logger.log('Nonce for Authz registered');
    return {status: 302, location: request.toUri()};
  }

  getClientIdentity(client_id: string): string {
    if (!client_id.startsWith('did')) {
      return client_id;
    }
    const clientIdIdentity = IdentityFactory.create(client_id);
    const aud = client_id;
    if (clientIdIdentity.isDerivable()) {
      const audienceIdentity = clientIdIdentity.deriveIdentity();
      return audienceIdentity.getDidUrl();
    }
    return aud;
  }

  private async authorizeForVerification(
    issuerUri: string,
    rp: OpenIDReliyingParty,
    verifiedAuthz: VerifiedBaseAuthzRequest,
  ) {
    this.logger.log('Authorize - Verification flow');
    const scopeAction = await getVerificationInfo(
      issuerUri,
      verifiedAuthz.authzRequest.scope,
    );
    if (!scopeAction) {
      throw new InvalidRequest('Invalid scope specified');
    }
    const aud = this.getClientIdentity(verifiedAuthz.authzRequest.client_id);
    const request = await this.processScopeAction(
      scopeAction,
      issuerUri,
      rp,
      {
        type: 'Verification',
        verifiedBaseAuthzRequest: verifiedAuthz,
      },
      aud,
    );
    this.logger.log('Nonce for Authz registered');
    return {status: 302, location: request.toUri()};
  }

  private async processScopeAction(
    scopeAction: VcScopeAction | VpScopeAction,
    issuerUri: string,
    rp: OpenIDReliyingParty,
    requestPurpose: RequestPurpose,
    aud: string,
  ): Promise<IdTokenRequest | VpTokenRequest> {
    let request: IdTokenRequest | VpTokenRequest;
    const authzEndpoint =
      requestPurpose.verifiedBaseAuthzRequest
      .validatedClientMetadata.authorizationEndpoint.endsWith(
        ':',
      )
        ? requestPurpose.verifiedBaseAuthzRequest.validatedClientMetadata
            .authorizationEndpoint + '//'
        : requestPurpose.verifiedBaseAuthzRequest.validatedClientMetadata
            .authorizationEndpoint;

    if (scopeAction.response_type === 'vp_token') {
      request = await rp.createVpTokenRequest(
        authzEndpoint,
        aud,
        issuerUri.concat(AUTHORIZATION.direct_post_endpoint),
        {
          type: 'Raw',
          presentationDefinition: scopeAction.presentation_definition!,
        },
        requestPurpose,
      );
      this.logger.log('VP Token Request created');
    } else if (scopeAction.response_type === 'id_token') {
      request = await rp.createIdTokenRequest(
        authzEndpoint,
        aud,
        issuerUri.concat(AUTHORIZATION.direct_post_endpoint),
        requestPurpose,
      );
      this.logger.log('ID Token Request created');
    } else {
      this.logger.error(
        `Unssuported response_type specified: ${scopeAction.response_type}`,
      );
      throw new InternalServerError(
        'Unssuported response_type specified',
        'internal_error',
      );
    }
    return request;
  }

  /**
   * Processes a direct post response containing the ID token.
   *
   * @param entityUri - The URI of the issuer.
   * @param idToken - The ID token sent by the holder.
   * @param vpToken - The VP token sent by the holder.
   * @param presentationSubmission - The VP submission sent with a VP Token.
   * @returns An object containing the status code and the location for redirection.
   */
  async directPost(
    entityUri: string,
    idToken?: string,
    vpToken?: string,
    presentationSubmission?: string,
  ) {
    const token = idToken ?? vpToken;
    if (!token) {
      throw new HttpError(
        400,
        AuthzErrorCodes.INVALID_REQUEST,
        'Neither id_token nor vp_token was specified',
      );
    }
    const tokenType = idToken ? TokenType.ID : TokenType.VP;
    const {payload} = decodeToken(token);
    const jwtPayload = payload as JWTPayload;
    if (!jwtPayload.nonce) {
      throw new BadRequestError(
        AuthzErrorCodes.INVALID_REQUEST,
        `${tokenType} must contain a nonce parameter`,
      );
    }

    try {
      const rp = await this.rules.buildRp(entityUri);
      const scopeAction = await this.rules.getScopeAction(
        entityUri,
        jwtPayload.nonce as string,
      );
      let types: string | undefined = undefined;
      if ('credential_types' in scopeAction) {
        types = scopeAction.credential_types;
      }
      if (scopeAction.response_type !== tokenType) {
        throw new InvalidRequest(
          `Token type not expected: ${scopeAction.response_type} - ${tokenType}`,
        );
      }

      const {holderDid, claimsData, ...responseData} =
        await this.rules.verifyToken(
          rp,
          token,
          tokenType,
          types,
          scopeAction.presentation_definition,
          presentationSubmission,
        );

      const externalVerification = await this.rules.verifyOnExternalData(
        true,
        entityUri,
        (payload as JwtPayload).state,
        holderDid,
        claimsData,
      );

      if (!externalVerification.verified) {
        throw new AccessDenied(
          'The provided data did not pass the content validation',
        );
      }

      if (responseData.redirectUri) {
        const authzResponse = new AuthorizationResponse(
          responseData.redirectUri,
          responseData.authzCode!,
          responseData.state,
        );
        return {status: 302, location: authzResponse.toUri()};
      } else {
        return {status: 200};
      }
    } catch (error: any) {
      await this.rules.verifyOnExternalData(
        false,
        entityUri,
        (payload as JwtPayload).state,
      );
      if (error instanceof OpenIdError) {
        if (error.redirectUri) {
          return this.rules.generateLocationErrorResponse(
            error.redirectUri,
            error.code,
            error.message,
            error.holderState,
          );
        }
        throw new HttpError(
          error.recommendedHttpStatus!,
          error.code,
          error.message,
        );
      }
      this.logger.error(error);
      throw new HttpError(500, 'server_error', error.message);
    }
  }

  /**
   * Grants an access token based on the provided parameters.
   *
   * @param issuerUri - The issuer URI.
   * @param tokenRequest - The request sent by the client.
   * @returns An object containing the status code and the access token information.
   * @throws HttpError if there are issues with the data provided with the client.
   */
  async grantAccessToken(
    issuerUri: string,
    tokenRequest: TokenRequest,
  ) {
    let signature;
    let pubKey;

    try {
      const keys_256r1 = await keysBackend(issuerUri, 'secp256r1');
      signature = (
        await SignatureProvider.generateProvider(
          keys_256r1.format,
          keys_256r1.type,
          keys_256r1.value,
        )
      );
      pubKey = signature.getPublicKey(PublicKeyFormat.JWK);
      const rp = await this.rules.buildRp(issuerUri);

      const tokenResponse = await rp.generateAccessToken(
        tokenRequest,
        false,
        issuerUri,
        pubKey,
      );

      return {
        status: 200,
        ...tokenResponse,
      };
    } catch (error: any) {
      if (error instanceof OpenIdError) {
        throw new HttpError(
          error.recommendedHttpStatus!,
          error.code,
          error.message,
        );
      }
      throw error;
    }
  }

  /**
   * Create a VP Token Request for Presentation Offer.
   *
   * @param issuerUri - The issuer URI.
   * @param scopeAction - Information of VP scope action and presentation definition.
   * @param state - Optional state to identify user
   * @returns An object containing the status code and the jwt with vp_token_request.
   * @throws HttpError if there are issues with the data provided with the client.
   */
  async createPresentationOffer(
    issuerUri: string,
    scopeAction: VpScopeAction,
    state?: string,
  ): Promise<VpTokenRequest | IdTokenRequest> {
    const rp = await this.rules.buildRp(issuerUri);
    this.logger.log('Openid RP instance created');
    if (!scopeAction) {
      throw new InvalidRequest('Invalid scope specified');
    }
    if (scopeAction.response_type === "vp_token") {
      const request =
        await rp.directVpTokenRequestForVerification(
          {
            type: 'Raw',
            presentationDefinition: scopeAction.presentation_definition!,
          },
          issuerUri.concat(AUTHORIZATION.direct_post_endpoint),
          {
            state: state,
            scope: scopeAction.scope,
          },
        );
        this.logger.log('Created VP token for verification');
        return request;
    } else {
      // ID Token
      const request = await rp.directIdTokenRequestForVerification(
        issuerUri.concat(AUTHORIZATION.direct_post_endpoint),
        {
          state: state,
          scope: scopeAction.scope,
        }
      );
      this.logger.log('Created ID token for verification');
      return request;
    }
  }
}

export enum TokenType {
  VP = 'vp_token',
  ID = 'id_token',
}
