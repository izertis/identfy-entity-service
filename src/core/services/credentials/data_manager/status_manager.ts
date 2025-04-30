import {match} from 'ts-pattern';
import {
  CredentialDataManager,
  CredentialDataResponse,
  DeferredCredentialData,
  InTimeCredentialData,
  Result,
  W3CVerifiableCredentialFormats,
} from 'openid-lib';
import {CREDENTIAL, EBSI} from '../../../../shared/config/configuration.js';
import {
  generateStatusListVcData
} from '../../../../shared/utils/revocation/status_list.utils.js';
import {
  STATUS_LIST_2021_VC
} from '../../../../shared/constants/credential_status.constants.js';
import {
  VERIFIABLE_ATTESTATION_TYPE,
  VERIFIABLE_CREDENTIAL_TYPE,
} from '../../../../shared/constants/credential.constants.js';
import {
  STATUS_LIST_CONTEXT
} from '../../../../shared/constants/status_list.constants.js';

export type RevocationInformation = {
  type: 'StatusList2021';
  statusList: string;
  listId: string;
};

export class StatusVcDataProvider extends CredentialDataManager {
  constructor(
    private revocationInformation: RevocationInformation,
    private statusPurpose: 'revocation' | 'suspension',
  ) {
    super();
  }

  static getAssociatedTypes(): string[] {
    return [
      VERIFIABLE_CREDENTIAL_TYPE,
      VERIFIABLE_ATTESTATION_TYPE,
      STATUS_LIST_2021_VC,
    ];
  }

  static getLinkedContext(): Record<string, string> {
    const result = {} as Record<string, string>;
    result[STATUS_LIST_2021_VC] = STATUS_LIST_CONTEXT;
    return result;
  }

  async getCredentialData(
    _types: string[],
    _holder: string,
  ): Promise<CredentialDataResponse> {
    let vcData: Record<string, any> = {};
    match(this.revocationInformation)
      .with({type: 'StatusList2021'}, data => {
        vcData = generateStatusListVcData(
          data.listId,
          this.statusPurpose,
          data.statusList,
        );
      })
      .exhaustive();
    return {
      type: 'InTime',
      data: vcData,
      schema: {
        id: EBSI.STATUS_LIST_2021_SCHEMA,
        type: CREDENTIAL.schema_type,
      },
      // TODO: CONSIDER TO ADD A TTL
      metadata: {},
    };
  }

  deferredExchange(_acceptanceToken: string): Promise<
    Result<
      | DeferredCredentialData
      | (InTimeCredentialData & {
          format: W3CVerifiableCredentialFormats;
          types: string[];
        }),
      Error
    >
  > {
    // We dont need to give support for this method. It should not be called
    throw new Error('Method not implemented.');
  }
}
