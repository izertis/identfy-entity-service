import { JWK } from "jose"

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
  serviceJwk?: JWK,
  redirect_uri: string,
  clientState?: string,
  type?: string
}

export interface NoncePostState {
  scope: string,
  clientDid: string,
  codeChallenge?: string,
  serviceJwk?: JWK
}

export interface NonceAccessTokenState {
  cNonce: string
}
