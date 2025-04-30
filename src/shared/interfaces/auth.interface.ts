import {JWTPayload} from 'jose';
import {VpScopeAction} from './scope-action.interface.js';
import {
  AuthorizationDetails,
  AuthzRequestWithJWT,
  AuthzResponseType,
  HolderMetadata,
  ServiceMetadata,
  TokenRequest,
} from 'openid-lib';

//* HTTP requests
export interface IAuthConfig_req {
  issuerUri: string;
}

export interface IAuthorizeCustom_req extends IAuthzRequest {
  issuerUri: string;
}

export interface IDirectPost_req {
  issuerUri: string;
  id_token?: string;
  vp_token?: string;
  presentation_submission?: string;
}

export interface IToken_req extends TokenRequest {
  issuerUri: string;
}

export interface PreAuthCodeData {
  client_id: string;
  vc_type: string;
}

// TODO: esta interfaz ya existe en la librería openid-lib (AuthzRequestWithJWT)
export interface IAuthzRequest {
  response_type: AuthzResponseType;
  client_id: string;
  redirect_uri: string;
  scope: string;
  issuer_state?: string;
  state?: string;
  authorization_details?: AuthorizationDetails[];
  nonce?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  client_metadata?: HolderMetadata | ServiceMetadata;
  request?: string;
}

export interface AccessTokenPayload extends JWTPayload {
  pin?: string;
  vc_types?: string[];
  verification_scope?: string;
}

export interface IPresentationOffer_req {
  issuerUri: string;
  verify_flow: VpScopeAction;
  state?: string;
}

export interface ExtendedAuthzRequest extends Partial<AuthzRequestWithJWT> {
  request_uri?: string,
  error?: string
}

export interface AuthResponse {
  code: string
}