import { JWTPayload } from "jose"

export interface CredentialJWt extends JWTPayload {
  vc: AccreditationToAttestPayload
}

export interface CredentialPayload {
  credentialSubject: {
    id: string,
    [propName: string]: unknown
  }
  [propName: string]: unknown
}

export interface AccreditationToAttestPayload extends CredentialPayload {
  credentialSubject: {
    id: string,
    accreditedFor: [
      {
        schemaId: string,
        types: string[],
        limitJurisdiction: string
      }
    ],
    reservedAttributeId: string,
    [propName: string]: unknown
  }
}
