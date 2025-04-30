import { z } from 'zod';

export default class RpcSchema {
  rpcMethod = z.object({
    jsonrpc: z.literal("2.0"),
    method: z.string(),
    id: z.string().optional(),
    params: z.object({}) // TODO: Verify this
  });
  onboardDidPayload = z.object({
    vc: z.string(),
    url: z.string(),
    did: z.string(),
  });
  addVerificationMethodPayload = z.object({
    url: z.string(),
    did: z.string(),
  });
  addVerificationRelationshipPayload = z.object({
    url: z.string(),
    did: z.string(),
    name: z.string(),
  });
  addTrustedIssuer = z.object({
    url: z.string(),
    did: z.string().optional(),
    taoDid: z.string(),
    taoAttributeId: z.string(),
    issuerType: z.string(), // TODO: VERIFY ENUMS
  });
  revokeAccreditation = z.object({
    url: z.string(),
    did: z.string().optional(),
    taoDid: z.string(),
    taoAttributeId: z.string(),
    revisionId: z.string(),
  });
  setTrustedIssuerData = z.object({
    url: z.string(),
    did: z.string(),
    vc: z.string(),
  });
  resolveCredentialOffer = z.object({
    credentialOffer: z.string()
  });
  requestVc = z.object({
    vcType: z.array(z.string()),
    did: z.string(),
    externalAddr: z.string(),
    credentialOffer: z.string(),
    vcForVp: z.array(z.string()).optional(),
    pinCode: z.number().optional(),
  });
  requestVcWithUri = z.object({
    vcType: z.array(z.string()),
    did: z.string(),
    externalAddr: z.string(),
    issuer: z.string(),
    vcForVp: z.array(z.string()).optional(),
    pinCode: z.number().optional(),
  });
  requestDeferredVc = z.object({
    issuer: z.string(),
    acceptanceToken: z.string(),
  });
  addIssuerProxy = z.object({
    url: z.string(),
    prefix: z.string(),
    testSuffix: z.string(),
    did: z.string(),
    headers: z.object({}).optional(),
  });
}