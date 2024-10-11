import { autoInjectable, singleton } from "tsyringe";
import { JWK, decodeJwt } from "jose";
import {
  CredentialRequest,
  CredentialResponse,
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
import {
  EBSI_TERM_OF_USE_TYPE,
} from "../../../shared/constants/ebsi.constants.js";
import {
  RevocationTypes,
  VcScopeAction
} from "../../../shared/interfaces/scope-action.interface.js";
import {
  STATUS_LIST_2021, STATUS_LIST_2021_SCHEMA, STATUS_LIST_2021_VC
} from "../../../shared/constants/credential_status.constants.js";
import {
  generateStatusListVcData
} from "../../../shared/utils/revocation/status_list.utils.js";
import { EBSI } from "../../../shared/config/configuration.js";
import { JwtPayload } from "jsonwebtoken";

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
    listId?: string,
    listIndex?: number,
  ) {
    try {
      const { payload } = decodeToken(accessToken);
      const tokenPayload = payload as AccessTokenPayload;
      const vcTypeRequested = !tokenPayload.isPreAuth ?
        this.rules.getVcTypesFromAccessToken(tokenPayload)
        : request.types;
      const scopeAction = await this.authRules.getIssuanceInfo(
        issuerUri,
        this.rules.getVcSpecificType(vcTypeRequested)
      );
      const revocationType = scopeAction.revocation;
      if (revocationType) {
        const validValues =
          Object.keys(RevocationTypes).map(key => RevocationTypes[key as keyof typeof RevocationTypes]);
        if (!validValues.includes(revocationType)) {
          throw new HttpError(
            500,
            "server_error",
            "Unssuported revocation type"
          )
        }
      }
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
      const proofIssuer = this.rules.getIssuerOfControlProof(request.proof);

      const vcIssuer = await this.rules.buildVcIssuer(
        issuerUri,
        vcTypeRequested,
        issuerDid,
        privateKeyJwk,
        nonceState.cNonce,
        scopeAction.credential_schema_address,
        scopeAction.is_deferred,
        tokenPayload,
        listId,
        listIndex,
        scopeAction.expires_in
      );
      const verifiedAccessToken = await vcIssuer.verifyAccessToken(
        accessToken,
        publicKeyJwk
      );
      if (tokenPayload.serviceWalletDid) {
        (verifiedAccessToken.payload as JwtPayload).sub = tokenPayload.serviceWalletDid as string;
      } else if (tokenPayload.isPreAuth) {
        // In our pre-auth flow implementation we check the validity of the code in this step.
        // For that reason, we don't have yet the DID of the user, so we have to manipulate the token
        // after it has been verified to include as subject the issuer of the control proof
        verifiedAccessToken.payload.sub = proofIssuer;
      }

      let credentialResponse: CredentialResponse;
      credentialResponse = await vcIssuer.generateCredentialResponse(
        verifiedAccessToken,
        request,
        W3CDataModel.V1,
        {
          getCredentialStatus: revocationType ? async (_types, _vcId, _holder) => {
            switch (revocationType) {
              case RevocationTypes.StatusList2021:
                if (listIndex === undefined || listId === undefined) {
                  throw new HttpError(
                    500,
                    "server_error",
                    "No status list index or ID provided"
                  );
                }
                return {
                  id: `${issuerDid}${listId}#${listIndex}`,
                  type: STATUS_LIST_2021,
                  statusPurpose: "revocation",
                  statusListIndex: `${listIndex}`,
                  statusListCredential: `${issuerUri}${listId}`
                }
            }
          } : undefined,
          getTermsOfUse: scopeAction.terms_of_use ? async (_types, _holder) => {
            return await this.getTermsOfUse(
              issuerDid,
              scopeAction
            );
          } : undefined
        }
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
    const scopeAction = await this.authRules.getIssuanceInfo(
      issuerUri,
      jwtPayload.vc_type
    );
    const vcIssuer = await this.rules.buildVcIssuer(
      issuerUri,
      jwtPayload.vc_type,
      issuerDid,
      privateKeyJwk,
      "",
      scopeAction.credential_schema_address,
      scopeAction.is_deferred,
      { isPreAuth: false },
      payload.list_id as string,
      payload.list_index as number,
      scopeAction.expires_in
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
          ],
          validUntil: response.validUntil,
          nbf: response.nbf,
          expiresInSeconds: response.expiresInSeconds
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
      W3CDataModel.V1,
      {
        getCredentialStatus: scopeAction.revocation ? async (_types, _vcId, _holder) => {
          switch (scopeAction.revocation) {
            case RevocationTypes.StatusList2021:
              if (payload.list_index === undefined || payload.list_id === undefined) {
                throw new HttpError(
                  500,
                  "server_error",
                  "No status list index provided"
                );
              }
              return {
                id: `${issuerDid}${payload.list_id}#${payload.list_index}`,
                type: STATUS_LIST_2021,
                statusPurpose: "revocation",
                statusListIndex: `${payload.list_index}`,
                statusListCredential: `${issuerUri}${payload.list_id}`
              }
            default:
              throw new HttpError(500, "server_error", "Unssuported revocation status type");
          }
        } : undefined,
        getTermsOfUse: scopeAction.terms_of_use ? async (types, holder) => {
          return await this.getTermsOfUse(
            issuerDid,
            scopeAction
          );
        } : undefined
      }
    );
    if (credentialResponse.c_nonce) {
      delete credentialResponse.c_nonce;
      delete credentialResponse.c_nonce_expires_in;
    }
    return { status: 200, ...credentialResponse };
  }

  private async getTermsOfUse(
    issuerDid: string,
    scopeAction: VcScopeAction
  ) {
    return {
      id: `${EBSI.tir_url}/issuers/${issuerDid}/attributes/${scopeAction.terms_of_use}`,
      type: EBSI_TERM_OF_USE_TYPE
    }
  }

  async issueStatusVC(
    issuerDid: string,
    issuerUri: string,
    listId: string,
    privateKeyJwk: JWK,
    statusList: string,
    statusPurpose: "revocation" | "suspension",
    revocationType: "StatusList2021"
  ) {
    let vcType: string[];
    let schema;
    let getData;
    switch (revocationType) {
      case "StatusList2021":
        vcType = [
          VERIFIABLE_CREDENTIAL_TYPE,
          VERIFIABLE_ATTESTATION_TYPE,
          STATUS_LIST_2021_VC,
        ]
        schema = STATUS_LIST_2021_SCHEMA;
        getData = async (_types: string[], _holder: string) => {
          return {
            data: generateStatusListVcData(
              listId,
              statusPurpose,
              statusList
            )
          }
        }
        break;
      default:
        throw new HttpError(500, "server_error", "Invalid recovation type");
    }
    const vcIssuer = await this.rules.buildVcIssuerForDirectIssuance(
      issuerUri,
      vcType,
      issuerDid,
      privateKeyJwk,
      schema,
      getData
    );
    const credentialResponse = await vcIssuer.generateVcDirectMode(
      listId,
      W3CDataModel.V1,
      vcType,
      "jwt_vc",
    );
    return { status: 200, ...{ credential: credentialResponse.credential } };
  }
}
