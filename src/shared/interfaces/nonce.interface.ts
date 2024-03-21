export interface NonceResponse {
  nonce: string,
  did: string,
  state?: string[]
}

export enum ResponseTypeOpcode {
  ISSUANCE = "0",
  VERIFICATION = "1",
}

export interface NonceAuthState {
  opcode: ResponseTypeOpcode,
  scope: string,
  code_challenge?: string,
  redirect_uri: string,
  clientState?: string,
  type?: string
}

export interface NoncePostState {
  scope: string,
  codeChallenge?: string,
}

export interface NonceAccessTokenState {
  cNonce: string
}
