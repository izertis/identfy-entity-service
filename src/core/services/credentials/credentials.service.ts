import {autoInjectable, singleton} from 'tsyringe';
import {decodeJwt} from 'jose';
import {
  ControlProof,
  CredentialRequest,
  CredentialResponse,
  InvalidProof,
  OpenIdError,
  W3CDataModel,
  decodeToken,
} from 'openid-lib';
import Logger from '../../../shared/classes/logger.js';
import CredentialsRules from './credentials.rules.js';
import {HttpError} from '../../../shared/classes/error/httperrors.js';
import {
  BearerTokenErrorCodes
} from '../../../shared/constants/error_codes.constants.js';
import {
  IAcceptanceTokenPayload
} from '../../../shared/interfaces/credentials.interface.js';
import {
  VERIFIABLE_ATTESTATION_TYPE,
  VERIFIABLE_CREDENTIAL_TYPE,
} from '../../../shared/constants/credential.constants.js';
import {AccessTokenPayload} from '../../../shared/interfaces/auth.interface.js';
import {
  EbsiAccreditationType,
  ONBOARD_VC,
  VERIFIABLE_ACCREDITATION_TYPE,
} from '../../../shared/constants/ebsi.constants.js';
import {StatusVcDataProvider} from './data_manager/status_manager.js';
import {keysBackend} from '../../../shared/utils/functions/auth.utils.js';
import {
  SignatureProvider
} from '../../../shared/classes/signature_provider/index.js';
import {PublicKeyFormat} from '../../../shared/types/keys.type.js';

@singleton()
@autoInjectable()
export default class CredentialsService {
  constructor(
    private logger: Logger,
    private rules: CredentialsRules,
  ) {}

  async issueCredential(
    accessToken: string,
    request: CredentialRequest,
    issuerUri: string,
    issuerDid: string,
    listId?: string,
    listIndex?: number,
    listProxy?: string,
  ) {
    try {
      const {payload} = decodeToken(accessToken);
      const tokenPayload = payload as AccessTokenPayload;
      let signature: SignatureProvider;
      const keys_256r1 = await keysBackend(issuerUri, 'secp256r1');
        signature = (
          await SignatureProvider.generateProvider(
            keys_256r1.format,
            keys_256r1.type,
            keys_256r1.value,
          )
        );
      const vcIssuer = await this.rules.buildVcIssuer(
        issuerUri,
        request.types,
        issuerDid,
        signature,
        listId,
        listIndex,
        listProxy,
        tokenPayload,
      );
      const verifiedAccessToken = await vcIssuer.verifyAccessToken(
        accessToken,
        await signature.getPublicKey(PublicKeyFormat.JWK),
      );
      let credentialResponse: CredentialResponse;
      if (
        tokenPayload.vc_types &&
        tokenPayload.vc_types?.includes(ONBOARD_VC)
      ) {
        // The did used with the proof is not yet registered
        const controlProof = ControlProof.fromJSON(request.proof);
        const nonceInProof = controlProof.getInnerNonce();
        const subjectDid = controlProof.getAssociatedIdentifier();
        if (nonceInProof !== tokenPayload.nonce) {
          throw new InvalidProof(
            `Invalid "nonce" parameter inside control proof`,
          );
        }
        credentialResponse = await vcIssuer.generateVcDirectMode(
          subjectDid,
          W3CDataModel.V1,
          [
            VERIFIABLE_CREDENTIAL_TYPE,
            VERIFIABLE_ATTESTATION_TYPE,
            ONBOARD_VC,
          ],
          'jwt_vc',
        );
      } else {
        credentialResponse = await vcIssuer.generateCredentialResponse(
          verifiedAccessToken,
          request,
          W3CDataModel.V1,
        );
      }
      this.logger.log(credentialResponse.credential);
      return {status: 200, ...credentialResponse};
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

  async issueDeferredCredential(
    acceptanceToken: string,
    issuerUri: string,
    issuerDid: string,
  ) {
    const payload = decodeJwt(acceptanceToken);
    const jwtPayload = payload as IAcceptanceTokenPayload;
    if (!jwtPayload.code || !jwtPayload.vc_type) {
      throw new HttpError(
        BearerTokenErrorCodes.INVALID_TOKEN.httpStatus,
        BearerTokenErrorCodes.INVALID_TOKEN.code,
        'The acceptance token provided is incorrect',
      );
    }
    let signature: SignatureProvider;
    const keys_256r1 = await keysBackend(issuerUri, 'secp256r1');
    signature = (
      await SignatureProvider.generateProvider(
        keys_256r1.format,
        keys_256r1.type,
        keys_256r1.value,
      )
    );
    const vcIssuer = await this.rules.buildVcIssuer(
      issuerUri,
      jwtPayload.vc_type, // TODO: Analyze effect
      issuerDid,
      signature,
      payload.list_id as string,
      payload.list_index as number,
      payload.list_proxy as string,
    );
    const credentialResponse = await vcIssuer.exchangeAcceptanceTokenForVc(
      acceptanceToken,
      W3CDataModel.V1,
    );
    if (credentialResponse.c_nonce) {
      delete credentialResponse.c_nonce;
      delete credentialResponse.c_nonce_expires_in;
    }
    this.logger.log(credentialResponse.credential);
    return {status: 200, ...credentialResponse};
  }

  async issueStatusVC(
    issuerDid: string,
    issuerUri: string,
    listId: string,
    statusList: string,
    statusPurpose: 'revocation' | 'suspension',
    revocationType: 'StatusList2021',
  ) {
    const vcIssuer = await this.rules.buildVcIssuerForStatusVc(
      issuerUri,
      issuerDid,
      statusPurpose,
      listId,
      statusList,
      revocationType,
    );
    const credentialResponse = await vcIssuer.generateVcDirectMode(
      listId,
      W3CDataModel.V1,
      StatusVcDataProvider.getAssociatedTypes(),
      'jwt_vc',
    );
    this.logger.log(credentialResponse.credential);
    return {status: 200, ...{credential: credentialResponse.credential}};
  }

  async ebsiDirectAccreditationIssuance(
    accreditationType: EbsiAccreditationType,
    holderDid: string,
    issuerUri: string,
    issuerDid: string,
  ) {
    const keys_256r1 = await keysBackend(issuerUri, 'secp256r1');
    const signature = (
      await SignatureProvider.generateProvider(
        keys_256r1.format,
        keys_256r1.type,
        keys_256r1.value,
      )
    );
    const vcAllTypes = [
      VERIFIABLE_ATTESTATION_TYPE,
      VERIFIABLE_CREDENTIAL_TYPE,
      VERIFIABLE_ACCREDITATION_TYPE,
      accreditationType,
    ];
    const vcIssuer = await this.rules.buildVcIssuer(
      issuerUri,
      vcAllTypes,
      issuerDid,
      signature,
    );
    const credentialResponse = await vcIssuer.generateVcDirectMode(
      holderDid,
      W3CDataModel.V1,
      [
        VERIFIABLE_CREDENTIAL_TYPE,
        VERIFIABLE_ATTESTATION_TYPE,
        VERIFIABLE_ACCREDITATION_TYPE,
        accreditationType,
      ],
      'jwt_vc',
    );
    return {status: 200, ...{credential: credentialResponse.credential}};
  }
}
