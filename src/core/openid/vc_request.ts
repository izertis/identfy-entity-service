import { JWK } from "jose";
import fetch from "node-fetch";
import { AuthorizationRequest } from "./authorization_request.js";
import {
  IdTokenAuthorizationResponse, VpTokenAuthorizationResponse,
} from "./authorization_response.js";
import { withCode, withPreAuthCode } from "./authentication_request.js";
import { CredentialRequest } from "./credential_request.js";
import {
  getCredentialIssuerJWKs,
  getIssuerMetadata
} from "./utils.js";
import { DeferredCredentialRequest } from "./deferred_credential_request.js";
import {
  AuthServerMetadata,
  CredentialOffer,
  CredentialResponse,
  IssuerMetadata,
  TokenResponse
} from "openid-lib";
import { extractQueryParameters } from "../../shared/utils/url.utils.js";
import {
  ExecutionFailed,
  FetchError,
  InfallibleError,
  InvalidParameters
} from "../../shared/classes/error/internalerror.js";
import { getAndCheckAuthMetadata } from "./metadata.js";
import { EBSI } from "../../shared/config/configuration.js";
import {
  SignatureProvider
} from "../../shared/classes/signature_provider/index.js";
import {
  crvToAlg,
  keysBackend
} from "../../shared/utils/functions/auth.utils.js";
import {
  ES256K_CODE,
  ES256_CODE
} from "../../shared/constants/jwa.constants.js";
import { PublicKeyFormat } from "../../shared/types/keys.type.js";

export class OpenId4VCI {
  constructor() { }

  static async resolveCredentialOffer(
    credentialOffer: string
  ): Promise<CredentialOffer> {
    let offerParameters: Record<string, any>;
    try {
      offerParameters = extractQueryParameters(credentialOffer);
    } catch {
      throw new InvalidParameters("Invalid DeepLink provided");
    }
    const hasCredentialOffer = "credential_offer" in offerParameters;
    const hasCredentialOfferUri = "credential_offer_uri" in offerParameters;
    if (hasCredentialOffer && hasCredentialOfferUri) {
      throw new InvalidParameters(
        "Both credential_offer and credential_offer_uri were present"
      );
    }
    if (hasCredentialOffer) {
      return this.parseCredentialOffer(offerParameters["credential_offer"]);
    }
    if (hasCredentialOfferUri) {
      return await this.fetchCredentialOffer(offerParameters[
        "credential_offer_uri"
      ]);
    }
    throw new InvalidParameters("Invalid parameters for credential-offer");
  }

  private static parseCredentialOffer(credentialOffer: string): CredentialOffer {
    try {
      return JSON.parse(credentialOffer);
    } catch {
      throw new InvalidParameters(
        "credential_offer parameter needs to be a JSON Object"
      );
    }
  }

  private static async fetchCredentialOffer(
    uri: string
  ): Promise<CredentialOffer> {
    try {
      const response = await fetch(uri);
      if (!response.ok) {
        throw new InvalidParameters(
          `Unable to retrieve credential-offer. Service responded with code ${
            response.status
          }`
        );
      }
      return await response.json() as any;
    } catch (error: any) {
      if (error instanceof TypeError) {
        throw new FetchError(
          "Unable to retrieve credential-offer. Invalid URL or connection issue"
        );
      }
      if (error instanceof SyntaxError) {
        throw new InvalidParameters(
          "Credential Offer data needs to be in JSON format"
        );
      }
      throw error;
    }
  }

  private async getMetadata(
    issuerUri: string,
  ): Promise<{
    authMetadata: AuthServerMetadata,
    issuerMetadata: IssuerMetadata,
  }> {
    const issuerMetadata = await getIssuerMetadata(
      issuerUri,
      EBSI.DISCOVERY_ISSUER_PATH
    );
    return {
      authMetadata: await getAndCheckAuthMetadata(
        issuerMetadata.authorization_server!, EBSI.DISCOVERY_PATH
      ),
      issuerMetadata,
    }
  }

  async requestVc(
    credentialRequested: string[],
    credentialOffer: CredentialOffer,
    externalAddr: string,
    did: string,
    pinCode?: number,
    credentialsForVp?: string[],
    signerOptions?: {
      header_typ?: string
      subResolver?: () => string,
      kidPrefix?: string,
      omitIssuer?: boolean
    },
  ): Promise<CredentialResponse> {
    const {
      authMetadata,
      issuerMetadata,
    } = await this.getMetadata(credentialOffer.credential_issuer);
    let signatureProvider;
    switch (authMetadata.request_object_signing_alg_values_supported) {
      case ES256_CODE as any:
        const keys_256r1 = (await keysBackend(externalAddr, "secp256r1"));
        if (!keys_256r1) {
          throw new ExecutionFailed(
            'Unssuported signing algorithm for VC Issuance'
          );
        }
        signatureProvider = await SignatureProvider.generateProvider(
          keys_256r1.format,
          keys_256r1.type,
          keys_256r1.value
        )

        break;
      case ES256K_CODE as any:
        const keys_256k1 = (await keysBackend(externalAddr, "secp256k1"));
        if (!keys_256k1) {
          throw new ExecutionFailed(
            'Unssuported signing algorithm for VC Issuance'
          );
        }
        signatureProvider = await SignatureProvider.generateProvider(
          keys_256k1.format,
          keys_256k1.type,
          keys_256k1.value
        )

        break;
      default:
        throw new InfallibleError('This should never happens');
    }
    const alg = await crvToAlg(
      await signatureProvider.getPublicKey(PublicKeyFormat.JWK).crv!
    );
    if (!authMetadata.request_object_signing_alg_values_supported?.includes(
      alg as any
    )) {
      throw new ExecutionFailed('Unssuported signing algorithm for VC Issuance');
    }
    const jwks = await getCredentialIssuerJWKs(`${authMetadata.jwks_uri}`);
    let tokenResponse: TokenResponse;
    if (credentialOffer.grants!.authorization_code) {
      // InTime
      tokenResponse = await this.processWithAuthorization(
        signatureProvider,
        authMetadata,
        issuerMetadata,
        externalAddr,
        jwks,
        did,
        credentialRequested,
        {
          issuerState: credentialOffer.grants!.authorization_code.issuer_state,
          credentialsForVp: credentialsForVp
        }
      )
    } else if (credentialOffer.grants![
      "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    ]) {
      const preCode = credentialOffer
        .grants!["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        ["pre-authorized_code"];
      if (!preCode) {
        throw new InvalidParameters("No pre-autorization code was given");
      }
      if (credentialOffer
        .grants!["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        .user_pin_required && !pinCode) {
        throw new InvalidParameters(
          "A pin code is needed to fulfil the pre-autorization flow"
        );
      }
      tokenResponse = await this.processWithPreAuthCode(
        authMetadata,
        preCode,
        pinCode,
      );
    } else {
      throw new ExecutionFailed('Grant type unssuported');
    }
    const credentialRequest = new CredentialRequest(signatureProvider);
    return await credentialRequest.sendCredentialRequest(
      tokenResponse,
      issuerMetadata.credential_endpoint,
      issuerMetadata.credential_issuer,
      credentialRequested,
      did,
      externalAddr,
      signerOptions
    );
  }

  async requestDeferredVc(
    acceptanceToken: string,
    issuerUri: string,
  ) {
    const issuerMetadata = await getIssuerMetadata(
      issuerUri,
      EBSI.DISCOVERY_ISSUER_PATH
    );
    const credentialRequest = new DeferredCredentialRequest();
    return await credentialRequest.sendRequest(
      issuerMetadata.deferred_credential_endpoint!,
      acceptanceToken,
    );
  }

  private async processWithAuthorization(
    signer: SignatureProvider,
    authMetadata: AuthServerMetadata,
    issuerMetadata: IssuerMetadata,
    externalAddr: string,
    jwks: JWK[],
    did: string,
    credential: string[],
    optionalParams?: {
      issuerState?: string
      credentialsForVp?: string[]
    }
  ): Promise<TokenResponse> {
    const authzRequest = new AuthorizationRequest(signer, authMetadata);
    const tokenRequest = await authzRequest.sendRequest(
      "openid",
      externalAddr,
      {
        issuer_state: optionalParams ? optionalParams.issuerState : undefined,
        authorization_details: [
          {
            type: 'openid_credential',
            format: 'jwt_vc',
            locations: [issuerMetadata.credential_issuer],
            types: credential
          }
        ],
        client_metadata: {
          jwks_uri: `${externalAddr}/auth/jwks`,
          authorization_endpoint: 'openid:'
        },
      },
      issuerMetadata.authorization_server!,
      jwks
    );
    let authzResponse;
    if (tokenRequest.response_type == 'id_token') {
      const idResponse = new IdTokenAuthorizationResponse(signer);
      authzResponse = await idResponse.sendIdToken(
        tokenRequest,
        did,
        externalAddr,
        issuerMetadata.authorization_server!
      );
    } else if (tokenRequest.response_type == 'vp_token') {
      const vpResponse = new VpTokenAuthorizationResponse(signer);
      authzResponse = await vpResponse.sendVpToken(
        tokenRequest,
        did,
        issuerMetadata.authorization_server!,
        optionalParams ?
          optionalParams.credentialsForVp ?
            optionalParams.credentialsForVp : []
          : [], // TODO: In a future, give service access to the DB
        externalAddr,
      );
    } else {
      throw new InfallibleError('This should never happens');
    }
    const authnRequest = withCode(signer, authzResponse.code, authMetadata);
    const authnResponse = await authnRequest.sendRequest(
      authMetadata.issuer,
      externalAddr
    );
    return authnResponse;
  }

  private async processWithPreAuthCode(
    authMetadata: AuthServerMetadata,
    code: string,
    pinCode?: number,
  ) {
    const authnRequest = withPreAuthCode(code, authMetadata,);
    const authnResponse = await authnRequest.sendRequest(pinCode);
    return authnResponse;
  }
}
