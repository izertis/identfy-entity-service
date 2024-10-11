export interface CredentialDataResponse {
  body: {
    [key: string]: any;
    _metadata?: ExternalMetadata
  },
  termsOfUse?: string[]
}

export interface ExternalMetadata {
  validUntil?: string;
  expiresInSeconds?: number;
  nbf?: string;
}
