export const AuthzErrorCodes = {
  INVALID_SCOPE: 'invalid_scope',
  INVALID_REQUEST: 'invalid_request',
  UNAUTHORIZED_CLIENT: 'unauthorized_client',
  UNSUPPORTED_RESPONSE_TYPE: 'unsupported_response_type',
  SERVER_ERROR: 'server_error',
  TEMPORARILY_UNAVAILABLE: 'temporarily_unavailable',
  ACCESS_DENIED: 'access_denied',
  VP_FORMATS_NOT_SUPPORTED: 'vp_formats_not_supported',
};

export const AuthnErrorCodes = {
  INVALID_REQUEST: {code: 'invalid_request', httpStatus: 400},
  INVALID_CLIENT: {code: 'invalid_client', httpStatus: 401},
  INVALID_GRANT: {code: 'invalid_grant', httpStatus: 400},
  UNAUTHORIZED_CLIENT: {code: 'unauthorized_client', httpStatus: 400},
  UNSUPPORTED_GRANT_TYPE: {code: 'unsupported_grant_type', httpStatus: 400},
  INVALID_SCOPE: {code: 'invalid_scope', httpStatus: 400},
};

export const BearerTokenErrorCodes = {
  INVALID_REQUEST: {code: 'invalid_request', httpStatus: 400},
  INVALID_TOKEN: {code: 'invalid_token', httpStatus: 401},
  INSUFFICIENT_SCOPE: {code: 'insufficient_scope', httpStatus: 403},
};

export const CredentialErrorCodes = {
  INVALID_CREDENTIAL_REQUEST: {
    code: 'invalid_credential_request',
    httpStatus: 400,
  },
  UNSUPPROTED_CREDENTIAL_TYPE: {
    code: 'unsupported_credential_type',
    httpStatus: 400,
  },
  UNSUPPORTED_CREDENTIAL_FORMAT: {
    code: 'unsupported_credential_format',
    httpStatus: 400,
  },
  INVALID_PROOF: {code: 'invalid_proof', httpStatus: 400},
};
