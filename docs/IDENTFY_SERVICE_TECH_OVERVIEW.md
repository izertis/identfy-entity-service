<p align="center">
    <picture>
      <img alt="identfy" src="./img/identfy.jpg" width="350" style="max-width: 100%;">
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


|  Configuration | File | ENV | Explanation | Default value |
|----------------|---------|-----|-------------|---------|
| BACKEND.url | backend:url | BACKEND_URL | Entity wallet backend url | No value |
| BACKEND.user | backend:user | BACKEND_USER | User to connect with backend | No value |
| BACKEND.pass | backend:pass | BACKEND_PASS | Pass to connect with backend | No value |
| BACKEND.issuance_flow_path | backend:issuance_flow_endpoint | BACKEND_ISSUANCE_FLOW_ENDPOINT | Path to use when requesting issuance information from the backend | /issuance-flow |
| BACKEND.verification_flow_path | backend:verification_flow_endpoint | BACKEND_VERIFICATION_FLOW_ENDPOINT | Path to use when requesting verification information from the backend | /verify-flow |
| AUTHORIZATION.issuer | authorization:issuer | ISSUER_URL | Prefix for authorization endpoint | Empty string |
| AUTHORIZATION.authorization_endpoint | authorization:authorization_endpoint | AUTHORIZATION_ENDPOINT | BackOffice authorization endpoint | No value |
| AUTHORIZATION.token_endpoint | authorization:token_endpoint | TOKEN_ENDPOINT | Endpoint for requesting BackOffice access tokens| No value |
| AUTHORIZATION.direct_post_endpoint | authorization:direct_post_endpoint | DIRECT_POST_ENDPOINT | Endpoint for delivery of authorization responses from the BackOffice | No value |
| AUTHORIZATION.jwks_uri | authorization:jwks_uri | JWKS_URI | Endpoint with BackOffice keys used by the service | No value |
| AUTHORIZATION.scopes_supported | authorization:scopes_supported | Not supported | List of supported scopes | No value |
| CREDENTIAL.vc_data_endpoint | credential:vc_data_endpoint | VC_DATA_ENDPOINT | Allows you to change the path used to request credential data | /credentials/external-data/ |
| CREDENTIAL.schema_type | credential:schema_type | SCHEMA_TYPE | Value of the schema type to be included in the VC schema specification | FullJsonSchemaValidator2021 |
| CREDENTIAL.deferred_vc_register | credential:deferred_vc_register | DEFERRED_VC_REGISTER | Path from endpoint to register acceptance tokens for deferred flow | /deferred/register/ |
| CREDENTIAL.deferred_vc_exchange | credential:deferred_vc_exchange | DEFERRED_VC_EXCHANGE | Endpoint path to exchange acceptance tokens for deferred credentials | /deferred/exchange |
| VERIFIER.vp_verification_endpoint | verifier:vc_data_endpoint |VP_VERIFICATION_ENDPOINT | Endpoint used to request an additional verification on the data according to the business logic | No value |
| SERVER.port | server:port | PORT | Port to be used by the service | 80 |
| SERVER.api_path | server:api_path | API_PATH | Path to be included in all calls to endpoints | /api |
| SERVER.time_fix | server:time_fix | TIME_FIX | This allows to generate dates in the future, only useful to avoid synchronization problems when working with authz servers that does not implement a clock tolerance, for example, some EBSI tests | 0 |
| LOGS.console.active | logs:console:active | Not supported | Enables console logs| true |
| LOGS.console.level | logs:console:level | Not supported | Indicates the level of logs to be displayed by console | debug |
| LOGS.file.active | logs:file:active | Not supported | Enables logging of log messages to a file | false |
| LOGS.file.level | logs:file:level | Not supported | Indicates the level of logs to be displayed on the console | debug |
| LOGS.file.path | logs:file:path | Not supported | Indicates the path to the log file | No value |
| LANGUAGE.allowed | language:allowed | Not supported | Array of supported languages | No value |
| LANGUAGE.default | language:default | Not supported | Default language in which to generate responses | No value |
| LANGUAGE.location | language:location | Not supported | Path to the directory with the specification of translations for each language | No value |
| NONCE_SERVICE.url | nonce_service:url | NONCE_SERVICE_URL | URL of the nonces management service | BACKEND_URL + /nonce-manager |
| EBSI.verify_terms_of_use | ebsi:verify_term_of_use | EBSI_TERMS_OF_USE | Allow to specify if the terms of use should be checked in a Verifiable Credential. This value should be true except for testing reasons | false |
| EBSI.did_registry | ebsi:didr_url | EBSI_DID_REGISTRY_URL | URL of EBSI's DID Registry | https://api-pilot.ebsi.eu/did-registry/v4/identifiers |
| EBSI.tir_url | ebsi:tir_url | TIR_URL | URL of EBSI's TI Registry | https://api-pilot.ebsi.eu/trusted-issuers-registry/v4 |

##### Required configuration

To achieve the correct operation of the service, it is necessary to provide a value for each variable that does not have a default value. Likewise, it is also required to provide four additional environment variables:
- **NODE_CONFIG_DIR**: Specifies the path to the directory with the configuration files.
- **NODE_ENV**: Specifies the execution environment, which will be used to select the configuration file to be loaded from the previously specified path. Specifically, the file with the same name as the value given to this variable will be loaded. By default its value is ***local***.
- **BACKEND_PASS**: To access the information stored in the backend, the service needs to authorize itself. This is the user that will be used to do so.
- **BACKEND_USER**: To access the information stored in the backend, the service needs to authorize itself. This is the password that will be used to do so.

## Overview of the code

### REST API

> This documentation of the REST API could be outdated so, we recommend reviewing algo de swagger definition.

Communication with the service is done via REST API. The repository contains an `openapi` specification in the `src` directory with the name `swagger.yaml`. Additionally, once the service is up, that specification can be checked with Swagger UI by accessing the `/api/docs` endpoint.

The service exposes the same endpoints as those defined by EBSI in its implementation guidelines, except that they receive additional parameters related to the keys to be used, in addition to the DID and the external address to be included. Therefore, this document will only focus on specifying the differentiating aspects.

#### /auth/authorize
[EBSI documentation](https://hub.ebsi.eu/conformance/learn/verifiable-credential-issuance#authorisation-request)
Endpoint that receives authorization requests from client Wallets. Additional parameters:
- **issuerUri**: Issuer's external address. In case the service is not exposed to the Internet and a BackOffice is used, it must be the address of the latter.
- **privateKeyJwk**: Private key to be used in JWK format.
- **publicKeyJwk**: Public key corresponding to the private key indicated in JWK format.

#### /auth/direct_post
[EBSI documentation](https://hub.ebsi.eu/conformance/learn/verifiable-credential-issuance#id-token-response)
Endpoint that receives authorization responses from client Wallets. Additional parameters:
- **issuerUri**: Issuer's external address. In case the service is not exposed to the Internet and a BackOffice is used, it must be the address of the latter.
- **privateKeyJwk**: Private key to be used in JWK format.

#### /auth/token
[EBSI documentation](https://hub.ebsi.eu/conformance/learn/verifiable-credential-issuance#token-request)
Endpoint that receives Access Token requests from client Wallets. Additional parameters:
- **issuerUri**: Issuer's external address. In case the service is not exposed to the Internet and a BackOffice is used, it must be the address of the latter.
- **privateKeyJwk**: Private key to be used in JWK format.
- **publicKeyJwk**: Public key corresponding to the private key indicated in JWK format.

#### /credentials
[EBSI documentation](https://hub.ebsi.eu/conformance/learn/verifiable-credential-issuance#credential-request)
Endpoint that receives credential requests from client wallets. Additional parameters:
- **issuerUri**: Issuer's external address. In case the service is not exposed to the Internet and a BackOffice is used, it must be the address of the latter.
- **issuerDid**: DID used by the Issuer and to be used as Issuer of the credential.
- **privateKeyJwk**: Private key to be used in JWK format.
- **publicKeyJwk**: Public key corresponding to the private key indicated in JWK format.

#### /credential_deferred
[EBSI documentation](https://hub.ebsi.eu/conformance/learn/verifiable-credential-issuance#deferred-credential-request)
Endpoint that can be used to exchange acceptance codes for deferred credentials. Additional parameters:
- **issuerUri**: Issuer's external address. In case the service is not exposed to the Internet and a BackOffice is used, it must be the address of the latter.
- **issuerDid**: DID used by the Issuer and to be used as Issuer of the credential.
- **privateKeyJwk**: Private key to be used in JWK format.
- **publicKeyJwk**: Public key corresponding to the private key indicated in JWK format.

#### Status Credential endpoint
The service also exposes an endpoint that is used to generated the status credentials related to a revocation strategy. This endpoint is specific of the solution and does not follow any This endpoint is specific to this solution and is therefore specially designed to work in conjunction with the Backend component. In case of interest in the endpoint itself, it is recommended to consult the `swagger.yaml` endpoint “credentials/status”.

### Prerequisites

The following components are required for the correct operation of the service:

#### Nonces management service
The service is responsible for the management of the nonces, but not for their storage. It is necessary to set up a second service or component that allows these values to be registered by associating them with an entity. Specifically, this component, which from now on we will call Nonce Manager, should expose the following endpoints:

- **POST /nonce**: It must allow to register a new nonce in the system. The body will include the associated client_id (`did`) and an optional state (`state`). Example of payload:
```json
{
  "did": "did:example:123",
  "state": ["123"]
}
```
- **PATCH /nonce/{nonce}**: It must allow to update a previous nonce in the system, being the key to identify it the nonce itself and not the associated DID. The body may include the associated client_id (`did`) or a state (`state`). Example of payload:
```json
{
  "state": ["123"]
}
```
- **DELETE /nonce/{nonce}**: It must allow the deletion of a nonce from the system.
- **GET /nonce/{nonce}**: It must allow to obtain a nonce from the system along with its associated data. Example of expected response:
```json
{
  "nonce": "123",
  "did": "did:example:123",
  "state": []
}
```

The Nonce Manager URL is specified by configuration to the credential issuing service.
Please have it mind that the Backend of this solution also implements this API, so it can be used as an alternative.

#### Obtaining data associated with a specific operation.
Due to its stateless nature, the service does not have the means to determine if the information provided by a user is correct, for example, it is not able to determine if the type of credential requested can actually be issued by the issuer it represents. Likewise, it is also unaware of information specific to the process itself, such as whether or not the credential is deferred, its scheme, the scope associated with the operation and the type of token to be delivered by the user (ID Token vs. VP Token). All this information is provided by the Identfy Backend by two differents endpoints, one for issuance and another for verification processes.

### Integrations with the Authentic Source
The service needs to perform queries to external sources to obtain the credential data and to perform a validation of the delivered data with the credentials of a VP according to the underlying business logic. In both cases, the service queries the backend, which knows the URL of other user services able to satisfy these demands. This corresponds to the integrations between the Wallet and the Authentic Source and the existing ones will be briefly outlined below.

#### Verifiable credential data management, deferred and pre-authorized flow.
The service is completely unaware of the underlying business logic, and consequently is unable to determine what data should be included in the verifiable credentials that are generated. Nor is it aware of whether a pre-authorized code is valid or, in the case of deferred flow, whether the credential in question is ready to be delivered to the user. For all these reasons, the service requires a component that is able to provide it with all this information. This component in question, as the service is programmed, should be mounted on the URL specified in the ***issuerUri*** parameter that appears in the endpoint specification. In practice, there is no problem if this component and the one in charge of managing cryptographic keys are the same.

The following endpoints should be exposed:

##### Data to be included in the credential for InTime and PreAuthorize flows.

The *path segment* to be used can be modified if desired through the configuration. The default is ***/credentials/external-data***.
- **GET {issuerUri}/credentials/external-data/?vc_type=abc&user_id=did:example:321?pin=111**: The parameters passed must specify the specific type of the credential being requested and the user's identifier, in other words, its DID or the pre-auth code in the pre-auth flow. Regarding the type of the credential, consider a credential whose types are `["VerifiableCredential", "VerifiableAttestation", "MyCustomType"]`; in this particular case, the type to be indicated in the URL should be the last one. The *pin* parameter is optional and is only included in the pre-auth flow in case the client included when obtaining an access token.

Regarding the expected response, this should be the user data to be included in the *credential_subject* field of the verifiable credential.

##### Deferred flow.
Two endpoints are identified. The paths of both can be modified if desired through the configuration. By default **/deferred/exchange** and **/deferred/register/** are used.
- **POST {issuerUri}/deferred/register/**: Requests the creation and registration of a deferred code to be given to a user for the issuance of a credential at a future time. The expected payload is:
```json
{
  "client_id": "did:example:123",
  "vc_type": "MyCustomType",
  "pin": "111"
}
```
The *pin* parameter is included when the deferred flow is combined with the pre-auth flow and onlye if the client specified it in the access token request. In that same case, the *client_id* parameter would be the pre-auth code sent by the user instead of its DID.

In response, a string is expected that is the deferred code to be used.

- **GET {issuerUri}/deferred/exchange/{code}**: Where *code* is the deferred code or acceptance token delivered by the user. This endpoint is used to obtain the credential associated with the deferred code or a new code.

The following is expected in response:
```ts
interface IExchangeDeferredCodeResponse {
  data?: Record<string, any>;
  code?: string;
}
```

Note that although both are optional, they should not be at the same time. In case the credential still cannot be generated, the new acceptance token must be specified in the *code* attribute, which in practice could be the same as the old one if desired.

#### External verification

This request is used to allow the Authentic Source to do a last verification on the data submitted by the user with a Verifiable Presentation. For example, if the credential has an identifier among its data, it may be necessary to validate its existence in a database to which only the Authentic Source has access. Similarly, this request can also be used by the latter to store data extracted from the VPs if it deems it necessary.

- **POST {issuerUri}/presentations/external-data/**: This is the endpoint and the expected payload is:
```json
{
  "valid": true, // Boolean
  "holderDid": "did:example:123", // String
  "state": "CustomState", // String and optional. It only apperas if the user specified a state in the VP Token
  "claimsData": {
    "data1": {
      "data1-1": "data",
      "data1-2": 123
    }
  }
}
```
Let's explain some of the parameters:
- `valid`: Boolean flag indicating whether the verification was successful. It will always be true unless there is a problem with the credentials presented, such as their signature or they do not comply with the schema. The service makes the request also when its value is false to inform the Authentic Source of the attempt by the party, although in this case only the state of the VP is given, if any.
- `claimsData`: They correspond to the data delivered by the user through a VP. It is important to note that the service does not deliver the credentials in their entirety, only the data of interest in these, which correspond to those indicated in the Presentation Definition. For example, if a credential with an “age” field was requested, then only this field and not the rest will be delivered to the Authentic Source. The object structure follows the same as indicated in the definition. For example, suppose you use the following definition:
```json
{
  "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
  "format": { "jwt_vc": { "alg": [ "ES256" ] }, "jwt_vp": { "alg": [ "ES256" ] } },
  "input_descriptors": [
    {
      "id": "same-device-in-time-credential",
      "format": { "jwt_vc": { "alg": [ "ES256" ] } },
      "constraints": {
        "fields": [
          {
            "path": [ "$.vc.type" ],
            "id": "vcType",
            "filter": {
              "type": "array",
              "contains": { "const": "CTWalletSameAuthorisedInTime" }
            }
          }
        ]
      }
    }
  ]
}
```
Then `claimsData` would be:
```json
{
  "same-device-in-time-credential": {
    "vcType": "CTWalletSameAuthorisedInTime"
  }
}
```

## Code of contribution

Read please the [contribution documentation](../CONTRIBUTING.md)