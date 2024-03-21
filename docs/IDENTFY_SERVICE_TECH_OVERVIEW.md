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


|  Configuration | File | ENV | Explanation | Default value |
|----------------|---------|-----|-------------|---------|
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
| SERVER.port | server:port | PORT | Port to be used by the service | 80 |
| SERVER.api_path | server:api_path | API_PATH | Path to be included in all calls to endpoints | /api |
| SERVER.scope_action | server:scope_action_endpoint | SCOPE_ACTION_ENDPOINT | Enpoint to be used to obtain Enpoint to be used to obtain the data associated with an operation | No value |
| PRE_AUTHORIZATION_ENDPOINT | pre-auth_endpoint | PRE_AUTH_ENDPOINT | Path for delivery of pre-authorization codes | /auth/token |
| LOGS.console.active | logs:console:active | Not supported | Enables console logs| true |
| LOGS.console.level | logs:console:level | Not supported | Indicates the level of logs to be displayed by console | debug |
| LOGS.file.active | logs:file:active | Not supported | Enables logging of log messages to a file | false |
| LOGS.file.level | logs:file:level | Not supported | Indicates the level of logs to be displayed on the console | debug |
| LOGS.file.path | logs:file:path | Not supported | Indicates the path to the log file | No value |
| LANGUAGE.allowed | language:allowed | Not supported | Array of supported languages | No value |
| LANGUAGE.default | language:default | Not supported | Default language in which to generate responses | No value |
| LANGUAGE.location | language:location | Not supported | Path to the directory with the specification of translations for each language | No value |
| NONCE_SERVICE.url | nonce_service:url | NONCE_SERVICE_URL | URL of the nonces management service | No value |
| DEVELOPER.allow_empty_vc | developer:allow_empty_vc | ALLOW_EMPTY_VC | Allows the issuance of empty credentials if the credential data cannot be retrieved | false |
| DEVELOPER.pre_authorize_client (Not implemented) | developer:pre-authorize_data_client | PRE_AUTHORIZE_DATA_CLIENT | Sets a default user in case user retrieval fails when exchanging a pre-authorized code | No value |
| DEVELOPER.pre_authorize_vc_type (Not implemented) | developer:pre-authorize_data_vc_type | PRE_AUTHORIZE_DATA_VC_TYPE | Sets a default credential type in case of failure of credential retrieval when exchanging a pre-authorized code | No value |

##### Required configuration

To achieve the correct operation of the service, it is necessary to provide a value for each variable that does not have a default value. Likewise, it is also required to provide two additional environment variables:
- **NODE_CONFIG_DIR**: Specifies the path to the directory with the configuration files.
- **NODE_ENV**: Specifies the execution environment, which will be used to select the configuration file to be loaded from the previously specified path. Specifically, the file with the same name as the value given to this variable will be loaded. By default its value is ***local***.

#### Developer mode

The service allows to activate a developer mode that makes it possible to "skip" the communication of the service with third parties to obtain data associated with the credentials, as well as any call related to the deferred and pre-authorized flows. Developer mode is enabled with the ***DEVELOPER.allow_empty_vc*** configuration. Once enabled, if requests for credential data fail, the service will generate and issue an empty credential. Likewise, this variable also works with the deferred flow, in which case the service generates a default code that can then be exchanged for an empty credential.

*Currenlty NOT IMPLEMENTED: In the case of the pre-authorized flow, it is necessary to combine the above variable with two additional ones: ***DEVELOPER.pre_authorize_client*** and ***DEVELOPER.pre_authorize_vc_type***, which allow to specify a user and a default credential type to be used when the retrieval of the data associated with the delivered code fails.*

## Overview of the code

### REST API

> This documentation of the REST API could be outdated so, we recommend reviewing algo de swagger definition.

Communication with the service is done via REST API. The repository contains an `openapi` specification in the `src` directory with the name `swagger.yaml`. Additionally, once the service is up, that specification can be checked with Swagger UI by accessing the `/api/docs` endpoint.

The service exposes the same endpoints as those defined by EBSI in its implementation guidelines, except that they receive additional parameters related to the keys to be used, in addition to the DID and the external address to be included. Therefore, this document will only focus on specifying the differentiating aspects.

#### /api/authorize
[EBSI documentation](https://hub.ebsi.eu/conformance/learn/verifiable-credential-issuance#authorisation-request)
Endpoint that receives authorization requests from client Wallets. Additional parameters:
- **issuerUri**: Issuer's external address. In case the service is not exposed to the Internet and a BackOffice is used, it must be the address of the latter.
- **privateKeyJwk**: Private key to be used in JWK format.
- **publicKeyJwk**: Public key corresponding to the private key indicated in JWK format.

#### /api/direct_post
[EBSI documentation](https://hub.ebsi.eu/conformance/learn/verifiable-credential-issuance#id-token-response)
Endpoint that receives authorization responses from client Wallets. Additional parameters:
- **issuerUri**: Issuer's external address. In case the service is not exposed to the Internet and a BackOffice is used, it must be the address of the latter.
- **privateKeyJwk**: Private key to be used in JWK format.

#### /api/token
[EBSI documentation](https://hub.ebsi.eu/conformance/learn/verifiable-credential-issuance#token-request)
Endpoint that receives Access Token requests from client Wallets. Additional parameters:
- **issuerUri**: Issuer's external address. In case the service is not exposed to the Internet and a BackOffice is used, it must be the address of the latter.
- **privateKeyJwk**: Private key to be used in JWK format.
- **publicKeyJwk**: Public key corresponding to the private key indicated in JWK format.

#### /api/credentials
[EBSI documentation](https://hub.ebsi.eu/conformance/learn/verifiable-credential-issuance#credential-request)
Endpoint that receives credential requests from client wallets. Additional parameters:
- **issuerUri**: Issuer's external address. In case the service is not exposed to the Internet and a BackOffice is used, it must be the address of the latter.
- **IssuerDid**: DID used by the Issuer and to be used as Issuer of the credential.
- **privateKeyJwk**: Private key to be used in JWK format.
- **publicKeyJwk**: Public key corresponding to the private key indicated in JWK format.

#### /api/credential_deferred
[EBSI documentation](https://hub.ebsi.eu/conformance/learn/verifiable-credential-issuance#deferred-credential-request)
Endpoint that can be used to exchange acceptance codes for deferred credentials. Additional parameters:
- **issuerUri**: Issuer's external address. In case the service is not exposed to the Internet and a BackOffice is used, it must be the address of the latter.
- **IssuerDid**: DID used by the Issuer and to be used as Issuer of the credential.
- **privateKeyJwk**: Private key to be used in JWK format.
- **publicKeyJwk**: Public key corresponding to the private key indicated in JWK format.

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

#### Obtaining data associated with a specific operation.
Due to its stateless nature, the service does not have the means to determine if the information provided by a user is correct, for example, it is not able to determine if the type of credential requested can actually be issued by the issuer it represents. Likewise, it is also unaware of information specific to the process itself, such as whether or not the credential is deferred, its scheme, the scope associated with the operation and the type of token to be delivered by the user (ID Token vs. VP Token). All this information must be provided by a new service whose URL must be specified in the service configuration.

- ***GET {SPECIFIED URL}?issuer=abc&credential_types=CustomType***: The endpoint requires two parameters, one of them being `ìssuer`, which corresponds to the ID of the endpoint and is obtained from the ***IssuerURI*** parameter that appears in the REST API endpoints of the service. Specifically, the ID will be considered as the last path segment of the URI. As for the second parameter, it corresponds to the type of the credential requested by the user. Example of expected response:
```json
{
  "scope": "customScope",
  "credential_types": "should coincide with the one specified in the request",
  "response_type": "can be either vp_token(WIP) or id_token",
  "credential_schema_address": "should be the URI in which the VC schema can be obtained",
  "is_deferred": false,
}
```

#### Verifiable credential data management, deferred and pre-authorized flow.
The service is completely unaware of the underlying business logic, and consequently is unable to determine what data should be included in the verifiable credentials that are generated. Nor is it aware of whether a pre-authorized code is valid or, in the case of deferred flow, whether the credential in question is ready to be delivered to the user. For all these reasons, the service requires a component that is able to provide it with all this information. This component in question, as the service is programmed, should be mounted on the URL specified in the ***issuerUri*** parameter that appears in the endpoint specification. In practice, there is no problem if this component and the one in charge of managing cryptographic keys are the same.

The following endpoints should be exposed:

##### Data to be included in the credential.
The *path segment* to be used can be modified if desired through the configuration. The default is ***/credentials/external-data***.
- **GET {issuerUri}/credentials/external-data/?vc_type=abc&user_id=did:example:321?pin=111**: The parameters passed must specify the specific type of the credential being requested and the user's identifier, in other words, its DID or the pre-auth code in the pre-auth flow. Regarding the type of the credential, consider a credential whose types are `["VerifiableCredential", "VerifiableAttestation", "MyCustomType"]`; in this particular case, the type to be indicated in the URL should be the last one. The *pin* parameter is optional and is only included in the pre-auth flow in case the client included when obtaining an access token.

Regarding the expected response, this should be the user data to be included in the *credential_subject* field of the verifiable credential.

##### Pre-authorized flow.
The *path segment* to be used can be modified if desired through the configuration. By default ***/auth/token*** is used.
- **GET {issuerURI}/auth/token/{preauth-code}?pin=123**: Where *preauth-code* corresponds to the pre-authorized code given by the user. The *pin* parameter is optional and will be included only if the user has indicated one in his request. The expected response is a JSON object with the following data:
```json
{
  "client_id": "did:example:123",
  "vc_type": "MyCustomType"
}
```
Where *client_id* is the DID of the user for which the delivered code is valid and *vc_type* is the type of credential that can be issued with this code.

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


## Code of contribution

Read please the [contribution documentation](../CONTRIBUTING.md)