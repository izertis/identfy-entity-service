import nconf from "nconf";
import yaml from "nconf-yaml";

const env = process.env.NODE_ENV || "production";
const configDir = process.env.NODE_CONFIG_DIR || "/usr/src/app/deploy/config";
nconf.file({ file: `${configDir}/${env}.yaml`, format: yaml });
console.info(`Using ${nconf.get("configName")} configuration from ${configDir}`);

export const AUTHORIZATION = {
  issuer: process.env.ISSUER_URL ||
    (nconf.get("authorization:issuer") as string) || "",
  authorization_endpoint:
    process.env.AUTHORIZATION_ENDPOINT ||
    (nconf.get("authorization:authorization_endpoint") as string),
  token_endpoint:
    process.env.TOKEN_ENDPOINT || (nconf.get("authorization:token_endpoint") as string),
  direct_post_endpoint:
    process.env.DIRECT_POST_ENDPOINT || (nconf.get("authorization:direct_post_endpoint") as string),
  jwks_uri: process.env.JWKS_URI || (nconf.get("authorization:jwks_uri") as string),
  scopes_supported: nconf.get("authorization:scopes_supported") as string[],
  response_types_supported: ["id_token"] as string[],
  response_modes_supported: ["query"] as string[],
  grant_types_supported: ["authorization_code"] as string[],
  subject_types_supported: ["public"] as string[],
  id_token_signing_alg_values_supported: ["ES256"] as string[],
  request_object_signing_alg_values_supported: ["ES256"] as string[],
  request_parameter_supported: true,
  request_uri_parameter_supported: false,
  token_endpoint_auth_methods_supported: ["private_key_jwt"] as string[],
  vp_formats_supported: {
    jwt_vp: {
      alg_values_supported: ["ES256"] as string[],
    },
    jwt_vc: {
      alg_values_supported: ["ES256"] as string[],
    },
  },
  subject_syntax_types_supported: ["did:key", "did:ebsi"] as string[],
  subject_trust_frameworks_supported: ["ebsi"] as string[],
  id_token_types_supported: [
    "subject_signed_id_token",
    "attester_signed_id_token"
  ] as string[],
};

export const CREDENTIAL = {
  vc_data_endpoint: process.env.VC_DATA_ENDPOINT ||
    (nconf.get("credential:vc_data_endpoint") as string) ||
    "/credentials/external-data/",
  schema_type: process.env.SCHEMA_TYPE ||
    (nconf.get("credential:schema_type") as string) ||
    "FullJsonSchemaValidator2021",
  deferred_vc_register: process.env.DEFERRED_VC_REGISTER ||
    (nconf.get("credential:deferred_vc_register") as string) ||
    "/deferred/register/",
  deferred_vc_exchange: process.env.DEFERRED_VC_EXCHANGE ||
    (nconf.get("credential:deferred_vc_exchange") as string) ||
    "/deferred/exchange",
};

export const SERVER = {
  port: process.env.PORT || (nconf.get("server:port") as number),
  api_path: process.env.API_PATH || (nconf.get("server:api_path")) || "/api",
  scope_action: process.env.SCOPE_ACTION_ENDPOINT ||
    nconf.get("server:scope_action_endpoint")
};

export const PRE_AUTHORIZATION_ENDPOINT = process.env.PRE_AUTH_ENDPOINT
  || nconf.get("pre-auth_endpoint")
  || "/auth/token"

export const LOGS = {
  console: {
    active: nconf.get("logs:console:active") as boolean || true,
    level: nconf.get("logs:console:level") as string || "debug",
  },
  file: {
    active: nconf.get("logs:file:active") as boolean || false,
    level: nconf.get("logs:file:level") as string || "debug",
    path: nconf.get("logs:file:path") as string,
  },
};

export const LANGUAGE = {
  allowed: nconf.get("language:allowed") as string[],
  default: nconf.get("language:default") as string,
  location: nconf.get("language:location") as string,
};

export const NONCE_SERVICE = {
  url: process.env.NONCE_SERVICE_URL || nconf.get("nonce_service:url") as string,
};

export const DEVELOPER = {
  allow_empty_vc: process.env.ALLOW_EMPTY_VC ?
    JSON.parse(process.env.ALLOW_EMPTY_VC) :
    ((nconf.get("developer:allow_empty_vc") as boolean) ?? false),
  pre_authorize_client: process.env.PRE_AUTHORIZE_DATA_CLIENT ||
    nconf.get("developer:pre-authorize_data_client"),
  pre_authorize_vc_type: process.env.PRE_AUTHORIZE_DATA_VC_TYPE ||
    nconf.get("developer:pre-authorize_data_vc_type"),
};
