export const RTAO_VC = 'VerifiableAttestationForTrustChain';
export const TAO_VC = 'VerifiableAccreditationToAccredit';
export const ATTEST_VC = 'VerifiableAccreditationToAttest';
export const ONBOARD_VC = 'VerifiableAuthorisationToOnboard';
export const VERIFIABLE_ACCREDITATION_TYPE = 'VerifiableAccreditation';
export const ACCREDITATIONS_TYPES = [
  ONBOARD_VC,
  ATTEST_VC,
  TAO_VC,
  RTAO_VC,
] as const;
export const EBSI_TERM_OF_USE_TYPE = 'IssuanceCertificate';
export const EBSI_ISSUERS_PATH = 'issuers';
export const EBSI_PROXIES_PATH = 'proxies';
export const EBSI_IDENTIFIER = 'Ebsi';
export type EbsiAccreditationType = (typeof ACCREDITATIONS_TYPES)[number];
export const EBSI_SUPPORT_OFFICE_DID = 'did:ebsi:zZeKyEJfUTGwajhNyNX928z';
export const EBSI_CONFORMANCE_RTAO_DID = 'did:ebsi:zjHZjJ4Sy7r92BxXzFGs7qD';
export const SCOPE_VP_ONBOARD = 'openid didr_invite';
export const SCOPE_TIR_ONBOARD = 'openid tir_invite';
export const SCOPE_TIR_WRITE = 'openid tir_write';
export const SCOPE_VP_DIDR_WRITE = 'openid didr_write';
