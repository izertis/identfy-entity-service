import {JWTPayload} from 'jose';
import {CredentialRequest} from 'openid-lib';
import {EbsiAccreditationType} from '../constants/ebsi.constants.js';

//* HTTP requests
export type ICredential_req = CredentialRequest & IBasicCredential_req;

export interface IBasicCredential_req {
  issuerUri: string;
  issuerDid: string;
  listIndex?: number;
  listId?: string;
  listProxy?: string;
}

export interface IAcceptanceTokenPayload extends JWTPayload {
  code?: string;
  vc_type?: string;
}

export interface IExchangeDeferredCodeResponse {
  data?: Record<string, any>;
  code?: string;
  validUntil?: string;
  expiresInSeconds?: number;
  nbf?: string;
}

export interface IStatusCredentialRequest {
  issuerDid: string;
  issuerUri: string;
  listId: string;
  statusList: string;
  statusPurpose: 'revocation' | 'suspension';
  revocationType: 'StatusList2021';
}

export interface IDirectEbsiAccreditationIssuanceRequest {
  accreditationType: EbsiAccreditationType;
  holderDid: string;
  issuerUri: string;
  issuerDid: string;
}
