import { IssuerTypesKeys } from "../types/ebsi.types.js";

export interface RpcMethod {
  jsonrpc: string;
  method: string;
  id?: string;
  params: Record<string, any>
}

export interface RpcResponse {
  jsonrpc: string;
  id?: string;
  result?: any,
  error?: Record<string, any>
}

export interface RpcError {
  code: number;
  message: string;
  data?: any;
}

export interface OnboardDidInterface {
  vc: string,
  did: string,
  url: string
}

export interface AddVerificationMethodInterface {
  url: string
  did: string
}

export interface AddVerificationRelationshipInterface {
  did: string,
  name: string,
  url: string
}

export interface SetTrustedIssuerDataInterface {
  url: string
  did: string,
  vc: string
}

export interface InsertTrustedIssuerInterface {
  url: string
  did: string,
  taoDid: string,
  taoAttributeId: string,
  issuerType: IssuerTypesKeys
}

export interface RevokeAccreditationInterface {
  url: string,
  did: string,
  taoDid: string,
  taoAttributeId: string,
  revisionId: string,
}

export interface ResolveCredentialOfferInterface {
  credentialOffer: string,
}

export interface RequestVcInterface {
  credentialOffer: string,
  vcType: string[],
  did: string,
  externalAddr: string,
  pinCode?: number,
  vcForVp?: string[],
}

export interface RequestVcWithUriInterface {
  issuer: string,
  vcType: string[],
  did: string,
  externalAddr: string,
  pinCode?: number,
  vcForVp?: string[]
}

export interface RequestDeferredVcInterface {
  acceptanceToken: string,
  issuer: string,
}

export interface AddIssuerProxy {
  did: string,
  prefix: string,
  testSuffix: string,
  url: string
  headers?: Record<string, any>,
}
