import {
  CredentialDataManager,
  CredentialDataResponse,
  DeferredCredentialData,
  InTimeCredentialData,
  W3CVerifiableCredentialFormats,
  Result,
} from 'openid-lib';
import fetch from 'node-fetch';
import {match} from 'ts-pattern';
import Logger from '../../../../shared/classes/logger.js';
import {
  CredentialDataResponse as ExternalDataResponse,
  ExternalMetadata,
} from '../../../../shared/interfaces/external.interface.js';
import {
  VERIFIABLE_ATTESTATION_TYPE,
  VERIFIABLE_CREDENTIAL_TYPE,
} from '../../../../shared/constants/credential.constants.js';
import {
  VERIFIABLE_ACCREDITATION_TYPE
} from '../../../../shared/constants/ebsi.constants.js';
import {
  AuthzErrorCodes,
  CredentialErrorCodes,
} from '../../../../shared/constants/error_codes.constants.js';
import {
  HttpError,
  InternalServerError,
} from '../../../../shared/classes/error/httperrors.js';
import {decodeJwt} from 'jose';
import {removeSlash} from '../../../../shared/utils/api.utils.js';
import {CREDENTIAL} from '../../../../shared/config/configuration.js';
import {
  IAcceptanceTokenPayload,
  IExchangeDeferredCodeResponse,
} from '../../../../shared/interfaces/credentials.interface.js';
import {
  RevocationTypes,
  VcScopeAction,
} from '../../../../shared/interfaces/scope-action.interface.js';
import {
  IdentityFactory
} from '../../../../shared/utils/identity/identity-factory.js';
import {
  AccessTokenPayload
} from '../../../../shared/interfaces/auth.interface.js';
import {crvToAlg} from '../../../../shared/utils/functions/auth.utils.js';
import {getIssuanceInfo} from '../../request_info/index.js';
import {
  SignatureProvider
} from '../../../../shared/classes/signature_provider/index.js';
import {PublicKeyFormat} from '../../../../shared/types/keys.type.js';

export function generateNoRevocationInfo(): RevocationStrategy {
  return {
    type: RevocationTypes.NoRevocation,
  };
}

export function generateStatusList2021Info(
  listId: string,
  listIndex: number,
  listProxy: string,
): RevocationStrategy {
  return {
    type: RevocationTypes.StatusList2021,
    listId,
    listIndex,
    listProxy,
  };
}

export type RevocationStrategy =
  | {type: RevocationTypes.NoRevocation}
  | {
      type: RevocationTypes.StatusList2021;
      listId: string;
      listIndex: number;
      listProxy: string;
    }
  | {
      type: RevocationTypes.EbsiAccreditationEntry;
    };

export abstract class DataManager extends CredentialDataManager {
  constructor(
    protected issuerUri: string,
    protected issuerDid: string,
    protected signature: SignatureProvider,
    protected kid: string,
    protected revocationStrategy: RevocationStrategy,
    protected logger: Logger,
    protected accessTokenPayload?: AccessTokenPayload,
  ) {
    super();
  }

  protected abstract generateCredential(
    vcData: ExternalDataResponse,
    holder: string,
    scopeAction: VcScopeAction,
    metadata: ExternalMetadata,
    vcType: string,
  ): InTimeCredentialData;

  /**
   * Allows to get the credential type apart from
   *  VerifiableAttestation and VerifiableCredential
   * @param types All the types of the credential
   * @returns A single type of a credential
   */
  private getVcSpecificType(types: string[]): string {
    const result = types.find(type => {
      return (
        type !== VERIFIABLE_ATTESTATION_TYPE &&
        type !== VERIFIABLE_CREDENTIAL_TYPE &&
        type !== VERIFIABLE_ACCREDITATION_TYPE
      );
    });
    if (!result) {
      throw new HttpError(
        CredentialErrorCodes.UNSUPPROTED_CREDENTIAL_TYPE.httpStatus,
        CredentialErrorCodes.UNSUPPROTED_CREDENTIAL_TYPE.code,
        `Types ${types} are not supported`,
      );
    }
    return result;
  }

  private async generateAcceptanceToken(
    deferredCode: string,
    vcType: string,
    subject: string,
  ): Promise<string> {
    const header = {
      alg: await crvToAlg(
        (await this.signature.getPublicKey(PublicKeyFormat.JWK)).crv!,
      ),
      kid: `${this.issuerDid}#${this.kid}`,
    };

    const payload: Record<string, any> = {
      code: deferredCode,
      vc_type: vcType,
    };
    match(this.revocationStrategy).with(
      {type: RevocationTypes.StatusList2021},
      data => {
        payload.list_id = data.listId;
        payload.list_index = data.listIndex;
        payload.list_proxy = data.listProxy;
      },
    );
    const jwt = await this.signature.signJwt(header, {
      ...payload,
      sub: subject,
    });
    return jwt;
  }

  private async registerDeferredVc(
    clientId: string,
    type: string,
  ): Promise<string> {
    let fetchResponse;
    const uri = removeSlash(this.issuerUri);
    const body: Record<string, any> = {
      client_id: clientId,
      vc_type: type,
    };
    if (this.accessTokenPayload && this.accessTokenPayload.pin) {
      body.pin = this.accessTokenPayload.pin;
    }
    try {
      fetchResponse = await fetch(`${uri}${CREDENTIAL.deferred_vc_register}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      });
    } catch (error) {
      throw new InternalServerError(
        "Can't register VC for deferred flow",
        AuthzErrorCodes.SERVER_ERROR,
      );
    }
    if (!fetchResponse.ok) {
      this.logger.error(
        `POST to register VC for deferred flow failed with status ${fetchResponse.status}.
        Error ${fetchResponse.body}`,
      );
      throw new InternalServerError(
        `Can't register VC for deferred flow"`,
        AuthzErrorCodes.SERVER_ERROR,
      );
    }
    const contentType = fetchResponse.headers.get('content-type') ?? '';

    if (contentType.includes('application/json')) {
      const json = await fetchResponse.json();
      return typeof json === 'string' ? json : JSON.stringify(json);
    } else if (contentType.includes('text/plain')) {
      return await fetchResponse.text();
    } else {
      throw new InternalServerError(
        `Unexpected response Content-Type: ${contentType}`,
        AuthzErrorCodes.SERVER_ERROR,
      );
    }
  }

  /**
   * Allows a deferred VC code to be exchanged for the credential itself
   * @param code The code to exchange
   * @param issuerUri The URI of the issuer
   * @returns The data of the VC or a new deferred code
   */
  private async exchangeCodeForVc(
    code: string,
  ): Promise<IExchangeDeferredCodeResponse> {
    let fetchResponse;
    const uri = removeSlash(this.issuerUri);
    try {
      fetchResponse = await fetch(
        `${uri}${CREDENTIAL.deferred_vc_exchange}/${code}`,
      );
    } catch (error) {
      throw new InternalServerError(
        "Can't recover VC for deferred flow",
        AuthzErrorCodes.SERVER_ERROR,
      );
    }
    if (!fetchResponse.ok) {
      this.logger.error(
        `GET to recover VC for deferred flow failed with status ${fetchResponse.status}.
        Error ${fetchResponse.body}`,
      );
      throw new InternalServerError(
        `Can't recover VC for deferred flow"`,
        AuthzErrorCodes.SERVER_ERROR,
      );
    }
    return (await fetchResponse.json()) as IExchangeDeferredCodeResponse;
  }

  private async getCredentialDataFromExternalSource(
    vcType: string,
    clientId: string,
  ): Promise<ExternalDataResponse> {
    try {
      const data = {
        vc_type: vcType,
        user_id: clientId,
      } as Record<string, string>;
      if (this.accessTokenPayload && this.accessTokenPayload.pin) {
        data.pin = this.accessTokenPayload && this.accessTokenPayload.pin;
      }
      const params = new URLSearchParams(Object.entries(data)).toString();
      const fetchResponse = await fetch(
        `${this.issuerUri}${CREDENTIAL.vc_data_endpoint}?${params}`,
        {
          signal: AbortSignal.timeout(20 * 1000),
        },
      );
      if (fetchResponse.status !== 200) {
        this.logger.error(
          `An error ocurred requesting VC data: ${fetchResponse.statusText}`,
        );
        throw new HttpError(
          500,
          AuthzErrorCodes.SERVER_ERROR,
          `Error retrieving VC data`,
        );
      }
      if (
        fetchResponse.headers.get('Content-Type') !== 'application/json' &&
        fetchResponse.headers.get('content-type') !== 'application/json'
      ) {
        this.logger.error(`VC Data received not in JSON format`);
        throw new HttpError(
          500,
          AuthzErrorCodes.SERVER_ERROR,
          `Error retrieving VC data`,
        );
      }
      return (await fetchResponse.json()) as ExternalDataResponse;
    } catch (error: any) {
      if (error instanceof HttpError) {
        throw error;
      }
      this.logger.error(`GET CREDENTIAL DATA ERROR: ${error.message}`);
      throw new HttpError(
        500,
        AuthzErrorCodes.SERVER_ERROR,
        'Error retrieving VC data',
      );
    }
  }

  async getCredentialData(
    types: string[],
    holder: string,
  ): Promise<CredentialDataResponse> {
    const specificType = this.getVcSpecificType(types);
    const scopeAction = await getIssuanceInfo(this.issuerUri, specificType);
    let clientId = holder;
    if (this.accessTokenPayload && this.accessTokenPayload.sub) {
      if (!this.accessTokenPayload.sub.startsWith('did:')) {
        clientId = this.accessTokenPayload.sub;
      }
    }
    if (scopeAction.is_deferred) {
      const code = await this.registerDeferredVc(clientId, specificType);
      const deferredCode = await this.generateAcceptanceToken(
        code,
        specificType,
        holder,
      );
      return {
        type: 'Deferred',
        deferredCode: deferredCode,
      };
    }
    // In-Time flow
    const vcData = await this.getCredentialDataFromExternalSource(
      specificType,
      clientId,
    );
    const metadata = vcData.body._metadata ?? {};
    metadata.expiresInSeconds =
      metadata.expiresInSeconds ?? scopeAction.expires_in;
    delete vcData.body._metadata;
    return this.generateCredential(
      vcData,
      holder,
      scopeAction,
      metadata,
      specificType,
    );
  }

  async deferredExchange(acceptanceToken: string): Promise<
    Result<
      | DeferredCredentialData
      | (InTimeCredentialData & {
          format: W3CVerifiableCredentialFormats;
          types: string[];
        }),
      Error
    >
  > {
    const payload = decodeJwt(acceptanceToken);
    const jwtPayload = payload as IAcceptanceTokenPayload;
    if (!jwtPayload.code || !jwtPayload.vc_type) {
      return Result.Err(
        new Error('The provided code is unknow or is not yet available'),
      );
    }
    const scopeAction = await getIssuanceInfo(
      this.issuerUri,
      jwtPayload.vc_type,
    );
    const response = await this.exchangeCodeForVc(jwtPayload.code);
    if (response.data) {
      const vcData = this.generateCredential(
        {
          body: response.data,
          termsOfUse: undefined,
        },
        jwtPayload.sub!,
        scopeAction,
        {
          validUntil: response.validUntil,
          expiresInSeconds: response.expiresInSeconds,
          nbf: response.nbf,
        },
        jwtPayload.vc_type,
      );
      return Result.Ok({
        ...vcData,
        format: 'jwt_vc' as W3CVerifiableCredentialFormats,
        types: [
          VERIFIABLE_CREDENTIAL_TYPE,
          VERIFIABLE_ATTESTATION_TYPE,
          jwtPayload.vc_type,
        ],
      });
    } else {
      return Result.Ok({
        type: 'Deferred',
        deferredCode: response.code,
      });
    }
  }

  async resolveCredentialSubject(
    accessTokenSubject: string,
    proofIssuer: string,
  ): Promise<string> {
    let credentialSubject = proofIssuer;
    const proofIssuerIdentity = IdentityFactory.create(proofIssuer);
    if (proofIssuerIdentity.isDerivable()) {
      const credentialSubjectIdentity = proofIssuerIdentity.deriveIdentity();
      credentialSubject = credentialSubjectIdentity.getDidUrl();
    }
    return credentialSubject;
  }
}
