import { JWK, JWTPayload } from "jose";
import { CredentialRequest } from "openid-lib";

//* HTTP requests
export type ICredential_req = CredentialRequest & IBasicCredential_req;

export interface IBasicCredential_req {
  issuerUri: string;
  issuerDid: string;
  privateKeyJwk: JWK;
  publicKeyJwk: JWK;
}

export interface IAcceptanceTokenPayload extends JWTPayload {
  code?: string;
  vc_type?: string
}

export interface IExchangeDeferredCodeResponse {
  data?: Record<string, any>;
  code?: string;
}
