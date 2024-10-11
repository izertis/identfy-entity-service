import { JWK, JWTPayload } from "jose";
import { CredentialRequest } from "openid-lib";
import { EbsiAccreditationType } from "shared/constants/ebsi.constants";

//* HTTP requests
export type ICredential_req = CredentialRequest & IBasicCredential_req;

export interface IBasicCredential_req {
  issuerUri: string;
  issuerDid: string;
  privateKeyJwk: JWK;
  publicKeyJwk: JWK;
  listIndex?: number;
  listId?: string;
}

export interface IAcceptanceTokenPayload extends JWTPayload {
  code?: string;
  vc_type?: string
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
  privateKeyJwk: JWK;
  statusList: string;
  statusPurpose: "revocation" | "suspension",
  revocationType: "StatusList2021"
}
