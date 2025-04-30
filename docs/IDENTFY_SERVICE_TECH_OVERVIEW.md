<p align="center">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="./img/identfy-logo-dark.svg">
      <source media="(prefers-color-scheme: light)" srcset="./img/identfy-logo-light.svg">
      <img alt="identfy" src="./img/identfy.png" width="350" style="max-width: 100%;">
    </picture>
</p>

<p align="center">
  <h4>
    An all-in-one solution to take control of your digital identity
  </h4>
</p>

<br/>

#  identfy Entity service - configuration and code overview

## Environmental variables description

The service can be configured by a file or by environment variables. It is also possible to combine both options, with variables prevailing over files in case of conflict. Note, however, that it is not possible to configure any attribute by variables, being necessary in such cases to use the file which must be in `yml` format. The repository includes several example configuration files in the `deploy` directory.

| Configuration                                             | File                                           | ENV                                | Explanation                                                           | Default value                                                       |
|-----------------------------------------------------------|------------------------------------------------|------------------------------------|-----------------------------------------------------------------------|---------------------------------------------------------------------|
| BACKEND.url                                               | backend:url                                    | BACKEND_URL                        | Entity wallet backend url                                             | No value                                                            |
| BACKEND.user                                              | backend:user                                   | BACKEND_USER                       | User to connect with backend                                          | No value                                                            |
| BACKEND.pass                                              | backend:pass                                   | BACKEND_PASS                       | Password to connect with backend                                          | No value                                                            |
| BACKEND.issuance_flow_path                                | backend:issuance_flow_endpoint                 | BACKEND_ISSUANCE_FLOW_ENDPOINT     | Path to use when requesting issuance information from the backend     | /issuance-flow                                                      |
| BACKEND.verification_flow_path                            | backend:verification_flow_endpoint             | BACKEND_VERIFICATION_FLOW_ENDPOINT | Path to use when requesting verification information from the backend | /verify-flow                                                        |
| BACKEND.authorizationToken                                | backend:authorizationToken                     | Not supported                      | Optional token to be used when authenticating to backend              | No value                                                            |
| AUTHORIZATION.issuer                                      | authorization:issuer                           | ISSUER_URL                         | Prefix for authorization endpoint                                     | Empty string                                                        |
| AUTHORIZATION.authorization_endpoint                      | authorization:authorization_endpoint           | AUTHORIZATION_ENDPOINT             | BackOffice authorization endpoint                                     | No value                                                            |
| AUTHORIZATION.token_endpoint                              | authorization:token_endpoint                   | TOKEN_ENDPOINT                     | Endpoint for requesting access tokens                      | No value                                                            |
| AUTHORIZATION.direct_post_endpoint                        | authorization:direct_post_endpoint             | DIRECT_POST_ENDPOINT               | Endpoint for processing of authorization responses  | No value                                                            |
| AUTHORIZATION.jwks_uri                                    | authorization:jwks_uri                         | JWKS_URI                           | Endpoint with BackOffice keys used by the service                     | No value                                                            |
| AUTHORIZATION.scopes_supported                            | authorization:scopes_supported                 | Not supported                      | List of supported scopes                                              | No value                                                            |
| CREDENTIAL.vc_data_endpoint                               | credential:vc_data_endpoint                    | VC_DATA_ENDPOINT                   | Path used to request credential data                                  | /credentials/external-data/                                         |
| CREDENTIAL.schema_type                                    | credential:schema_type                         | SCHEMA_TYPE                        | Type of schema used for VC validation                                 | FullJsonSchemaValidator2021                                         |
| CREDENTIAL.deferred_vc_register                           | credential:deferred_vc_register                | DEFERRED_VC_REGISTER               | Path to register acceptance tokens for deferred flow                  | /deferred/register/                                                 |
| CREDENTIAL.deferred_vc_exchange                           | credential:deferred_vc_exchange                | DEFERRED_VC_EXCHANGE               | Endpoint path to exchange acceptance tokens for deferred credentials  | /deferred/exchange                                                  |
| CREDENTIAL.skip_vc_verification                           | credential:skip_vc_verification                | SKIP_VC_VERIFICATION               | List of VC schemas that will skip logic verification           | []                                                                  |
| VERIFIER.vp_verification_endpoint                         | verifier:vc_data_endpoint                      | VP_VERIFICATION_ENDPOINT           | Endpoint used to request additional validation of presentation data | /presentations/external-data/                                       |
| SERVER.port                                               | server:port                                    | PORT                               | Port to be used by the service                                        | 80                                                                  |
| SERVER.api_path                                           | server:api_path                                | API_PATH                           | Path to be included in all calls to endpoints                         | /api                                                                |
| SERVER.request_size_limit                                 | server:request_size_limit                      | REQUEST_SIZE_LIMIT                 | Limit for request payload size                                        | 200kb                                                               |
| SERVER.time_fix                                           | server:time_fix                                | TIME_FIX                           | Used to adjust timestamps to avoid clock skew issues                  | 0                                                                   |
| LOGS.console.active                                       | logs:console:active                            | Not supported                      | Enables console logs                                                  | true                                                                |
| LOGS.console.level                                        | logs:console:level                             | Not supported                      | Level of console logging                                              | debug                                                               |
| LOGS.file.active                                          | logs:file:active                               | Not supported                      | Enables file logging                                                  | false                                                               |
| LOGS.file.level                                           | logs:file:level                                | Not supported                      | Level of file logging                                                 | debug                                                               |
| LOGS.file.path                                            | logs:file:path                                 | Not supported                      | Path to the file where logs will be written                           | No value                                                            |
| LANGUAGE.allowed                                          | language:allowed                               | Not supported                      | List of supported languages                                           | No value                                                            |
| LANGUAGE.default                                          | language:default                               | Not supported                      | Default language                                                      | No value                                                            |
| LANGUAGE.location                                         | language:location                              | Not supported                      | Directory for translation files                                       | No value                                                            |
| NONCE_SERVICE.url                                         | nonce_service:url                              | NONCE_SERVICE_URL                  | URL of the nonce management service                                   | BACKEND_URL + /nonce-manager                                        |
| EBSI.verify_terms_of_use                                  | ebsi:verify_term_of_use                        | EBSI_TERMS_OF_USE                  | Whether to check terms of use in credentials                          | false                                                               |
| EBSI.did_registry                                         | ebsi:didr_url                                  | EBSI_DID_REGISTRY_URL              | EBSI DID Registry URL                                                 | https://api-pilot.ebsi.eu/did-registry/v5/identifiers         |
| EBSI.tir_url                                              | ebsi:tir_url                                   | TIR_URL                            | EBSI Trusted Issuers Registry URL                                     | https://api-pilot.ebsi.eu/trusted-issuers-registry/v5         |
| EBSI.status_list_2021_schema                              | ebsi:status_list_schema                        | Not supported                      | Status List 2021 schema URL                                           | https://api-pilot.ebsi.eu/trusted-schemas-registry/...        |
| EBSI.discovery_path                                       | ebsi:discovery:path                            | Not supported                      | OpenID configuration path                                             | .well-known/openid-configuration                                    |
| EBSI.discovery_issuer_path                                | ebsi:discovery:issuer:path                     | Not supported                      | OpenID issuer path                                                    | .well-known/openid-credential-issuer                                |
| EBSI.did_registry_rpc_endpoint                            | ebsi:did:registry:rpc:endpoint                 | Not supported                      | JSON-RPC endpoint for EBSI DID Registry                               | https://api-pilot.ebsi.eu/did-registry/v5/jsonrpc             |
| EBSI.ti_registry_rpc_endpoint                             | ebsi:ti:registry:rpc:endpoint                  | Not supported                      | JSON-RPC endpoint for EBSI TIR                                        | https://api-pilot.ebsi.eu/trusted-issuers-registry/v5/jsonrpc |
| EBSI.ti_registry                                           | ebsi:ti:registry:path                           | Not supported                      | URL to EBSI TIR                                                       | https://api-pilot.ebsi.eu/trusted-issuers-registry/v5         |
| EBSI.besu_rpc_endpoint                                     | ebsi:besu:rpc:endpoint                          | Not supported                      | JSON-RPC endpoint for Besu ledger                                     | https://api-pilot.ebsi.eu/ledger/v4/blockchains/besu          |
| EBSI.max_time_did_document_verification_method_in_seconds | ebsi:max:time:did:document:verification:method | Not supported                      | Max time of verification method (in ms)                                | 2 years                                                             |
| EBSI.auth_ebsi_server_url                                 | ebsi:auth:server:url                            | Not supported                      | Auth server URL for EBSI                                              | https://api-pilot.ebsi.eu/authorisation/v4                   |                                                        |


##### Required configuration

To ensure the correct operation of the service, values must be provided for all configuration variables that do not define a default. These can be set as environment variables or through a YAML configuration file, which is the recommended approach for values that are unlikely to change often (e.g., service endpoints, supported formats).
The service requires the following additional environment variables:
- NODE_CONFIG_DIR: Path to the directory containing the YAML configuration files.
- NODE_ENV: Indicates the environment to use. The service will load the file matching the value of this variable from the directory specified by NODE_CONFIG_DIR. Defaults to local.

Among the required variables, special attention should be given to:
- BACKEND_USER and BACKEND_PASS: These are used by the service to authenticate against the BackOffice in order to retrieve credential issuance and verification information. By default, the BackOffice creates a user service with password service. These values can be changed through the BackOffice's admin interface and should be customized in non-test environments.

## General overview

### Prerequisites

The following components are required for the correct operation of the service:

#### Nonce and State Management

The service includes an abstraction for managing state through the `StateManager` interface. This design makes it possible to implement different strategies for storing state information, such as local memory or external databases. Currently, the only implementation provided is `RemoteManager`, which uses an external HTTP service to store, update, retrieve, and delete nonce-related data.

This external state service must support storing any JSON structure as the value associated with a given nonce. While the data format is flexible, the service must follow a specific API structure to ensure compatibility.

The expected endpoints for the external state service are:

- **POST /nonce**
  Registers a new nonce and its associated state.
  Example request:
  ```json
  {
    "nonce": "abc123",
    "state": {
      "type": "Issuance",
      "metadata": {
        "vcTypes": ["ExampleCredential"]
      }
    }
  }
  ```

- **PATCH /nonce/{nonce}**
Updates the state of an existing nonce.
Example request:
```json
{
  "state": {
    "updated": true
  }
}
```

- **GET /nonce/{nonce}**
Retrieves the stored state associated with a given nonce.
Example response:
```json
{
  "nonce": "abc123",
  "state": {
    "type": "Issuance",
    "metadata": {
      "vcTypes": ["ExampleCredential"]
    }
  }
}
```

- **DELETE /nonce/{nonce}**
Deletes the given nonce and its associated data.

The remote state service’s base URL is defined by the configuration variable NONCE_SERVICE_URL.

Note: The backend component included in this solution already implements this API and can be used directly as a remote state provider.

### REST API

The service exposes a REST API that follows the implementation guidelines defined by EBSI. The API specification is available in OpenAPI format and can be accessed in two ways:

- **In the repository**: You can find the OpenAPI definition at [`src/swagger.yaml`](./src/swagger.yaml).
- **Through Swagger UI**: Once the service is running, you can access the interactive API documentation at [`/api/docs`](http://localhost/api/docs).

### Integration with the Authentic Source

The service is responsible for handling the full issuance and verification flows, including credential construction, schema validation, and cryptographic signature checks. However, these operations often involve identifiers or values that need to be validated against business logic or real-world data—such as determining whether a particular identifier corresponds to an actual, authorized subject.

To support this, the service integrates with an intermediary component (typically referred to as the **BackOffice**) that exposes a set of endpoints used to retrieve or validate such information. From the service's perspective, this component acts as a gateway: it receives the queries and is responsible for resolving them—either using its own logic or by delegating to one or more **Authentic Sources**.

In practice, the BackOffice does not hold the authoritative data itself but knows how to obtain it from the appropriate external systems. The service is agnostic to the internal mechanisms of the BackOffice and focuses only on submitting the relevant requests.

The base URL for these interactions is specified via the `BACKEND_URL` environment variable. All data retrieval and validation operations (e.g., issuing credentials, checking the context of a VP, handling deferred flows) are conducted against this URL through the associated endpoints.

## Code of contribution

Read please the [contribution documentation](../CONTRIBUTING.md)