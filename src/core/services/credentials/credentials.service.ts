import { autoInjectable, singleton } from "tsyringe";
import { JWK, JWTPayload, decodeJwt } from "jose";
import {
  CredentialRequest,
  OpenIdError,
  W3CDataModel,
  decodeToken
} from "openid-lib";
import Logger from "../../../shared/classes/logger.js";
import CredentialsRules from "./credentials.rules.js";
import AuthRules from "../auth/auth.rules.js";
import { HttpError } from "../../../shared/classes/errors.js";
import {
  BearerTokenErrorCodes
} from "../../../shared/constants/error_codes.constants.js";
import NonceService from "../nonce/nonce.service.js";
import {
  IAcceptanceTokenPayload
} from "../../../shared/interfaces/credentials.interface.js";
import {
  VERIFIABLE_ATTESTATION_TYPE,
  VERIFIABLE_CREDENTIAL_TYPE
} from "../../../shared/constants/credential.constants.js";
import {
  ExtendedCredentialDataOrDeferred
} from "openid-lib/dist/src/core/credentials/types.js";
import { AccessTokenPayload } from "../../../shared/interfaces/auth.interface.js";

@singleton()
@autoInjectable()
export default class CredentialsService {
  constructor(
    private logger: Logger,
    private rules: CredentialsRules,
    private authRules: AuthRules,
    private nonceService: NonceService,
  ) { }


  async issueCredential(
    accessToken: string,
    request: CredentialRequest,
    issuerUri: string,
    issuerDid: string,
    privateKeyJwk: JWK,
    publicKeyJwk: JWK,
  ) {
    try {
      accessToken = accessToken.replace("Bearer", "");
      const { payload } = decodeToken(accessToken);
      const tokenPayload = payload as AccessTokenPayload;
      const vcTypeRequested = !tokenPayload.isPreAuth ?
        this.rules.getVcTypesFromAccessToken(tokenPayload)
        : request.types;
      const scopeAction = await this.authRules.getIssuanceInfo(
        issuerUri,
        this.rules.getVcSpecificType(vcTypeRequested)
      );
      if (!tokenPayload.nonce) {
        throw new HttpError(
          BearerTokenErrorCodes.INVALID_TOKEN.httpStatus,
          BearerTokenErrorCodes.INVALID_TOKEN.code,
          "The access token is incorrect"
        )
      }
      const nonceResponse = await this.nonceService.getNonce(
        tokenPayload.nonce as string
      );
      if (!nonceResponse) {
        throw new HttpError(
          BearerTokenErrorCodes.INVALID_TOKEN.httpStatus,
          BearerTokenErrorCodes.INVALID_TOKEN.code,
          "The access token is incorrect"
        )
      }
      const nonceState = NonceService.verifyAccessTokenNonceState(nonceResponse.state!);
      const vcIssuer = await this.rules.buildVcIssuer(
        issuerUri,
        vcTypeRequested,
        issuerDid,
        privateKeyJwk,
        nonceState.cNonce,
        scopeAction.credential_schema_address,
        scopeAction.is_deferred,
        tokenPayload
      );
      const verifiedAccessToken = await vcIssuer.verifyAccessToken(
        accessToken,
        publicKeyJwk
      );
      // In our pre-auth flow implementation we check the validity of the code in this step.
      // For that reason, we don't have yet the DID of the user, so we have to manipulate the token
      // after it has been verified to include as subject the issuer of the control proof
      const proofIssuer = this.rules.getIssuerOfControlProof(request.proof);
      verifiedAccessToken.payload.sub = proofIssuer;
      const credentialResponse = await vcIssuer.generateCredentialResponse(
        verifiedAccessToken,
        request,
        W3CDataModel.V1
      );
      if (credentialResponse.c_nonce) {
        this.logger.log(credentialResponse.credential);
        this.nonceService.updateChallengeNonce(nonceResponse.nonce, credentialResponse.c_nonce!)
      }
      return { status: 200, ...credentialResponse };
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

  async issueDeferredCredential(
    acceptanceToken: string,
    issuerUri: string,
    issuerDid: string,
    privateKeyJwk: JWK,
    publicKeyJwk: JWK,
  ) {
    const payload = decodeJwt(acceptanceToken);
    const jwtPayload = payload as IAcceptanceTokenPayload;
    if (!jwtPayload.code || !jwtPayload.vc_type) {
      throw new HttpError(
        BearerTokenErrorCodes.INVALID_TOKEN.httpStatus,
        BearerTokenErrorCodes.INVALID_TOKEN.code,
        "The acceptance token provided is incorrect"
      );
    }
    const scopeAction = await this.authRules.getIssuanceInfo(issuerUri, jwtPayload.vc_type);
    const vcIssuer = await this.rules.buildVcIssuer(
      issuerUri,
      jwtPayload.vc_type,
      issuerDid,
      privateKeyJwk,
      "",
      scopeAction.credential_schema_address,
      scopeAction.is_deferred,
      { isPreAuth: false }
    );
    const credentialResponse = await vcIssuer.exchangeAcceptanceTokenForVc(
      jwtPayload.code,
      async (token) => {
        const response = await this.rules.exchangeCodeForVc(token, issuerUri);
        const result: ExtendedCredentialDataOrDeferred = {
          format: "jwt_vc",
          types: [
            VERIFIABLE_CREDENTIAL_TYPE,
            VERIFIABLE_ATTESTATION_TYPE,
            jwtPayload.vc_type!
          ]
        };
        if (response.data) {
          result.data = {
            id: jwtPayload.sub,
            ...response.data
          };
          return result;
        } else {
          result.deferredCode = response.code;
          return result;
        }
      },
      W3CDataModel.V1
    );
    if (credentialResponse.c_nonce) {
      delete credentialResponse.c_nonce;
      delete credentialResponse.c_nonce_expires_in;
    }
    return { status: 200, ...credentialResponse };
  }
}
