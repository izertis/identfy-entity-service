import nconf from 'nconf';
import yaml from 'nconf-yaml';
import {resolve} from 'path';
import {SRC_DIR} from '../utils/path.utils.js';
import { getNumber, getString } from './utils.js';

const env = process.env.NODE_ENV || 'production';
const configDir =
  process.env.NODE_CONFIG_DIR || resolve(SRC_DIR, '../deploy/config');
nconf.file({file: `${configDir}/${env}.yaml`, format: yaml});
console.info(
  `Using ${nconf.get('configName')} configuration from ${configDir}`,
);

export const AUTHORIZATION = {
  issuer:
    process.env.ISSUER_URL ||
    (nconf.get('authorization:issuer') as string) ||
    '',
  authorization_endpoint:
    process.env.AUTHORIZATION_ENDPOINT ||
    (nconf.get('authorization:authorization_endpoint') as string),
  token_endpoint:
    process.env.TOKEN_ENDPOINT ||
    (nconf.get('authorization:token_endpoint') as string),
  direct_post_endpoint:
    process.env.DIRECT_POST_ENDPOINT ||
    (nconf.get('authorization:direct_post_endpoint') as string),
  jwks_uri:
    process.env.JWKS_URI || (nconf.get('authorization:jwks_uri') as string),
  scopes_supported: nconf.get('authorization:scopes_supported') as string[],
  response_types_supported: ['id_token'] as string[],
  response_modes_supported: ['query'] as string[],
  grant_types_supported: ['authorization_code'] as string[],
  subject_types_supported: ['public'] as string[],
  id_token_signing_alg_values_supported: ['ES256', 'ES256K'] as string[],
  request_object_signing_alg_values_supported: ['ES256', 'ES256K'] as string[],
  request_parameter_supported: true,
  request_uri_parameter_supported: false,
  token_endpoint_auth_methods_supported: ['private_key_jwt'] as string[],
  vp_formats_supported: {
    jwt_vp: {
      alg_values_supported: ['ES256'] as string[],
    },
    jwt_vc: {
      alg_values_supported: ['ES256'] as string[],
    },
  },
  subject_syntax_types_supported: ['did:key', 'did:ebsi'] as string[],
  subject_trust_frameworks_supported: ['ebsi'] as string[],
  id_token_types_supported: [
    'subject_signed_id_token',
    'attester_signed_id_token',
  ] as string[],
};

export const CREDENTIAL = {
  vc_data_endpoint:
    process.env.VC_DATA_ENDPOINT ||
    (nconf.get('credential:vc_data_endpoint') as string) ||
    '/credentials/external-data/',
  schema_type:
    process.env.SCHEMA_TYPE ||
    (nconf.get('credential:schema_type') as string) ||
    'FullJsonSchemaValidator2021',
  deferred_vc_register:
    process.env.DEFERRED_VC_REGISTER ||
    (nconf.get('credential:deferred_vc_register') as string) ||
    '/deferred/register/',
  deferred_vc_exchange:
    process.env.DEFERRED_VC_EXCHANGE ||
    (nconf.get('credential:deferred_vc_exchange') as string) ||
    '/deferred/exchange',
  skip_vc_verification:
    loadListVariable(process.env.SKIP_VC_VERIFICATION) ||
    (nconf.get('credential:skip_vc_verification') as string[]) ||
    [],
};

export const VERIFIER = {
  vp_verification_endpoint:
    process.env.VP_VERIFICATION_ENDPOINT ||
    (nconf.get('verifier:vc_data_endpoint') as string) ||
    '/presentations/external-data/',
};

export const SERVER = {
  port: process.env.PORT || (nconf.get('server:port') as number),
  api_path: process.env.API_PATH || nconf.get('server:api_path') || '/api',
  request_size_limit:
    process.env.REQUEST_SIZE_LIMIT ||
    nconf.get('server:request_size_limit') ||
    '200kb',
  time_fix: process.env.TIME_FIX || nconf.get('server:time_fix') || 0,
};

export const BACKEND = {
  url: process.env.BACKEND_URL || nconf.get('backend:url'),
  user: process.env.BACKEND_USER || nconf.get('backend:user'),
  password: process.env.BACKEND_PASS || nconf.get('backend:pasword'),
  issuance_flow_path:
    process.env.BACKEND_ISSUANCE_FLOW_ENDPOINT ||
    nconf.get('backend:issuance_flow_endpoint') ||
    '/issuance-flow',
  verification_flow_path:
    process.env.BACKEND_VERIFICATION_FLOW_ENDPOINT ||
    nconf.get('backend:verification_flow_endpoint') ||
    '/verify-flow',
  authorizationToken: nconf.get('backend:authorizationToken') as string,
};

export const PRE_AUTHORIZATION_ENDPOINT =
  process.env.PRE_AUTH_ENDPOINT ||
  nconf.get('pre-auth_endpoint') ||
  '/auth/token';

export const LOGS = {
  console: {
    active: (nconf.get('logs:console:active') as boolean) || true,
    level: (nconf.get('logs:console:level') as string) || 'debug',
  },
  file: {
    active: (nconf.get('logs:file:active') as boolean) || false,
    level: (nconf.get('logs:file:level') as string) || 'debug',
    path: nconf.get('logs:file:path') as string,
  },
};

export const LANGUAGE = {
  allowed: nconf.get('language:allowed') as string[],
  default: nconf.get('language:default') as string,
  location: nconf.get('language:location') as string,
};

export const NONCE_SERVICE = {
  url:
    process.env.NONCE_SERVICE_URL ||
    (nconf.get('nonce_service:url') as string) ||
    `${BACKEND.url}/nonce-manager`,
};

export const EBSI = {
  verify_terms_of_use: process.env.EBSI_TERMS_OF_USE
    ? JSON.parse(process.env.EBSI_TERMS_OF_USE)
    : ((nconf.get('ebsi:verify_term_of_use') as boolean) ?? false),
  did_registry:
    process.env.EBSI_DID_REGISTRY_URL ||
    nconf.get('ebsi:didr_url') ||
    'https://api-pilot.ebsi.eu/did-registry/v5/identifiers',
  tir_url:
    process.env.TIR_URL ||
    nconf.get('ebsi:tir_url') ||
    'https://api-pilot.ebsi.eu/trusted-issuers-registry/v5',
  STATUS_LIST_2021_SCHEMA:
    nconf.get('ebsi:status_list_schema') ||
    'https://api-pilot.ebsi.eu/trusted-schemas-registry/v3/schemas/z7DmpwC9doRxZrtQ9PBjz8qQgGWqojkGExELnrw1x8qdi',
  DISCOVERY_PATH: getString("ebsi:discovery:path", ".well-known/openid-configuration"),
  DISCOVERY_ISSUER_PATH: getString("ebsi:discovery:issuer:path", ".well-known/openid-credential-issuer"),
  DID_REGISTRY_RPC_ENDPOINT: getString("ebsi:did:registry:rpc:endpoint", "https://api-pilot.ebsi.eu/did-registry/v5/jsonrpc"),
  TI_REGISTRY_RPC_ENDPOINT: getString("ebsi:ti:registry:rpc:endpoint", "https://api-pilot.ebsi.eu/trusted-issuers-registry/v5/jsonrpc"),
  BESU_RPC_ENDPOINT: getString("ebsi:besu:rpc:endpoint", "https://api-pilot.ebsi.eu/ledger/v4/blockchains/besu"),
  MAX_TIME_DID_DOCUMENT_VERIFICATION_METHOD_IN_SECONDS: getNumber("ebsi:max:time:did:document:verification:method", (2 * 365 * 24 * 3600 * 1000)),
  AUTH_EBSI_SERVER_URL: getString("ebsi:auth:server:url", "https://api-pilot.ebsi.eu/authorisation/v4"),
};

function loadListVariable(data: string | undefined) {
  if (data) {
    return data.split(',');
  }
  return undefined;
}
