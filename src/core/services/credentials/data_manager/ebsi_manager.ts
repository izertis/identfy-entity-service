import {match} from 'ts-pattern';
import {DataManager, RevocationStrategy} from './index.js';
import Logger from '../../../../shared/classes/logger.js';
import {
  CredentialDataResponse as ExternalDataResponse,
  ExternalMetadata,
} from '../../../../shared/interfaces/external.interface.js';
import {
  RevocationTypes,
  VcScopeAction,
} from '../../../../shared/interfaces/scope-action.interface.js';
import {
  InTimeCredentialData,
  W3CCredentialStatus,
  W3CTermsOfUse,
} from 'openid-lib';
import {
  ACCREDITATIONS_TYPES,
  EBSI_ISSUERS_PATH,
  EBSI_PROXIES_PATH,
  EBSI_TERM_OF_USE_TYPE,
  ONBOARD_VC,
} from '../../../../shared/constants/ebsi.constants.js';
import {
  CREDENTIAL,
  EBSI
} from '../../../../shared/config/configuration.js';
import {
  AccessTokenPayload
} from '../../../../shared/interfaces/auth.interface.js';
import {
  SignatureProvider
} from '../../../../shared/classes/signature_provider/index.js';

export class EbsiDataManager extends DataManager {
  private constructor(
    protected issuerUri: string,
    protected issuerDid: string,
    protected signature: SignatureProvider,
    protected kid: string,
    protected revocationStrategy: RevocationStrategy,
    protected logger: Logger,
    protected accessTokenPayload?: AccessTokenPayload,
  ) {
    super(
      issuerUri,
      issuerDid,
      signature,
      kid,
      revocationStrategy,
      logger,
      accessTokenPayload,
    );
  }

  static async buildManager(
    issuerUri: string,
    issuerDid: string,
    signature: SignatureProvider,
    revocationStrategy: RevocationStrategy,
    kid: string,
    logger: Logger,
    accessTokenPayload?: AccessTokenPayload,
  ) {
    return new EbsiDataManager(
      issuerUri,
      issuerDid,
      signature,
      kid,
      revocationStrategy,
      logger,
      accessTokenPayload,
    );
  }

  protected generateCredential(
    vcData: ExternalDataResponse,
    holder: string,
    scopeAction: VcScopeAction,
    metadata: ExternalMetadata,
    vcType: string,
  ): InTimeCredentialData {
    let vcTermsOfUse: W3CTermsOfUse | W3CTermsOfUse[] | undefined = undefined;
    const isAccreditation = (
      ACCREDITATIONS_TYPES as unknown as string[]
    ).includes(vcType);

    if (isAccreditation) {
      this.revocationStrategy = {type: RevocationTypes.EbsiAccreditationEntry};
      if (vcData.termsOfUse) {
        const termOfUseArray = [];
        for (const termOfUse of vcData.termsOfUse) {
          termOfUseArray.push({
            id: `${EBSI.tir_url}/issuers/${this.issuerDid}/attributes/${termOfUse}`,
            type: EBSI_TERM_OF_USE_TYPE,
          });
        }
        vcTermsOfUse =
          termOfUseArray.length === 1 ? termOfUseArray[0] : termOfUseArray;
      }
      metadata.expiresInSeconds = 2 * 365 * 24 * 3600;
    } else {
      vcTermsOfUse = this.buildTermsOfUse(scopeAction);
    }
    return {
      type: 'InTime',
      data: {
        id: holder,
        ...vcData.body,
      },
      schema: {
        id: scopeAction.credential_schema_address,
        type: CREDENTIAL.schema_type,
      },
      status: this.buildCredentialStatus(vcData, holder, vcType),
      termfOfUse: vcTermsOfUse,
      metadata,
    };
  }

  private buildTermsOfUse(
    scopeAction: VcScopeAction,
  ): undefined | W3CTermsOfUse {
    if (scopeAction.terms_of_use) {
      return {
        id: `${EBSI.tir_url}/issuers/${this.issuerDid}/attributes/${scopeAction.terms_of_use}`,
        type: EBSI_TERM_OF_USE_TYPE,
      };
    }
    return undefined;
  }

  private buildCredentialStatus(
    vcData: ExternalDataResponse,
    holder: string,
    vcType: string,
  ): undefined | W3CCredentialStatus {
    return match(this.revocationStrategy)
      .with({type: RevocationTypes.NoRevocation}, _ => {
        return undefined;
      })
      .with({type: RevocationTypes.StatusList2021}, data => {
        return {
          id: `${this.issuerDid}${data.listId}#${data.listIndex}`,
          type: RevocationTypes.StatusList2021,
          statusPurpose: 'revocation', // TODO: This should be indicated by the backOffice
          statusListIndex: `${data.listIndex}`,
          statusListCredential: `${EBSI.tir_url}/${EBSI_ISSUERS_PATH}/${this.issuerDid}/${EBSI_PROXIES_PATH}/0x${data.listProxy}${data.listId}`,
        };
      })
      .with({type: RevocationTypes.EbsiAccreditationEntry}, _ => {
        if (vcType === ONBOARD_VC) {
          return undefined;
        }
        return {
          id: `${EBSI.tir_url}/issuers/${holder}/attributes/${vcData.body.reservedAttributeId}`,
          type: RevocationTypes.EbsiAccreditationEntry,
        };
      })
      .exhaustive();
  }
}
