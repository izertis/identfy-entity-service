import { JWTPayload } from "jose";
import {
  AuthorizationDetails,
  AuthzResponseType,
  HolderMetadata,
  ServiceMetadata,
  TokenRequest
} from "openid-lib";

//* HTTP requests
export interface IAuthConfig_req {
  issuerUri: string;
}

export interface IAuthorizeCustom_req extends IAuthzRequest {
  issuerUri: string;
  privateKeyJwk: string;
  publicKeyJwk: string;
}

export interface IDirectPost_req {
  issuerUri: string,
  privateKeyJwk: string;
  id_token?: string;
  vp_token?: string;
  presentation_submission?: string;
}

export interface IToken_req extends TokenRequest {
  issuerUri: string;
  privateKeyJwk: string;
  publicKeyJwk: string;
}

export interface PreAuthCodeData {
  client_id: string;
  vc_type: string;
}

export interface IAuthzRequest {
  response_type: AuthzResponseType;
  client_id: string;
  redirect_uri: string;
  scope: string;
  issuer_state?: string;
  state?: string;
  authorization_details?: string | AuthorizationDetails[];
  nonce?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  client_metadata?: string | HolderMetadata | ServiceMetadata;
}

export interface AccessTokenPayload extends JWTPayload {
  isPreAuth: boolean;
  pinCode?: string;
  vcType?: string;
}
