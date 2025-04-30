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

#  identfy Entity service

## Considerations

Although the service is technically stateless, the protocol itself is not, since it requires storing certain information about the user's session. Consequently, the service relegates these responsibilities to other entities, which it contacts via HTTP requests. Thus, in order for the service to function correctly, it is necessary to have one or more entities, depending on how it is considered, to fulfill these responsibilities.


## Prerequisites

### Identity and cryptographic key management

The microservice is designed to operate in conjunction with a BackOffice system that manages user identity, key material, and DID resolution. Rather than expecting cryptographic keys, DIDs, or issuer metadata to be passed in every request, the service retrieves this information itself from the configured environment and support services.

This architecture assumes that the BackOffice prepares the required context in advance: the subject's DID, the cryptographic keys to use for signing, and the supported issuance and verification flows. The microservice then acts as a functional layer that builds and processes the necessary OpenID for Verifiable Credential (OID4VC) requests and responses. The BackOffice is responsible for orchestrating these operations and triggering the appropriate endpoints.

It is recommended to consult the service’s REST API specification to understand which flows are supported and what configuration is expected.


## Configuration and code overview

There is a deeper explanation of the [configuration and code overview](./IDENTFY_SERVICE_TECH_OVERVIEW.md)



## Code of contribution

Read please the [contribution documentation](../CONTRIBUTING.md)