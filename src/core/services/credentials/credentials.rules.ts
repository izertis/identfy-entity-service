import { autoInjectable, singleton } from "tsyringe";
import {
  W3CVcIssuer,
  CredentialSupportedBuilder,
  BaseControlProof,
  ControlProof,
  GetCredentialData,
  W3CVerifiableCredential
} from "openid-lib";
import fetch from 'node-fetch';
import {
  JWK,
  JWTPayload,
  SignJWT,
  calculateJwkThumbprint,
  importJWK
} from "jose";
import { Resolver } from "did-resolver";
import {
  HttpError,
  InternalServerError
} from "../../../shared/classes/errors.js";
import {
  AuthzErrorCodes,
  BearerTokenErrorCodes,
  CredentialErrorCodes
} from "../../../shared/constants/error_codes.constants.js";
import { getResolver as keyDidResolver } from "@cef-ebsi/key-did-resolver";
import {
  CREDENTIAL,
  EBSI
} from "../../../shared/config/configuration.js";
import {
  SUPPORTED_SIGNATURE_ALG
} from "../../../shared/config/supported_alg.js";
import {
  IExchangeDeferredCodeResponse
} from "../../../shared/interfaces/credentials.interface.js";
import {
  VERIFIABLE_ATTESTATION_TYPE,
  VERIFIABLE_CREDENTIAL_TYPE
} from "../../../shared/constants/credential.constants.js";
import Logger from "../../../shared/classes/logger.js";
import { removeSlash } from "../../../shared/utils/api.utils.js";
import {
  AccessTokenPayload
} from "../../../shared/interfaces/auth.interface.js";
import { getResolver as ebsiDidResolver } from "@cef-ebsi/ebsi-did-resolver";
import {
  CredentialDataResponse
} from "../../../shared/interfaces/external.interface.js";
import {
  STATUS_LIST_2021_VC
} from "../../../shared/constants/credential_status.constants.js";
import {
  STATUS_LIST_CONTEXT
} from "../../../shared/constants/status_list.constants.js";

@singleton()
@autoInjectable()
export default class CredentialsRules {

  didResolver = new Resolver({
    ...keyDidResolver(),
    ...ebsiDidResolver({
      registry: EBSI.did_registry,
    })
  });

  constructor(private logger: Logger) { }

  /**
   * Generate an instance of W3CVcIssuer that is able to generate
   * VC for both the deferred and In-TIme flows
   * @param issuerUri The URI of the issuer
   * @param vcTypes The VC types that will be supported
   * @param issuerDid The DID of the issuer
   * @param privateKeyJwk The privateKey that will be used to sign the VC
   * @param expectedCNonce The expected c_nonce for the control proof
   * @param vcSchema The schema identifier for the VC
   * @param isDeferred A flag that indicated if the VC should follow the deferred flow
   * @returns An instance of W3CVcIssuer
   */
  async buildVcIssuer(
    issuerUri: string,
    vcTypes: string | string[],
    issuerDid: string,
    privateKeyJwk: JWK,
    expectedCNonce: string,
    vcSchema: string,
    isDeferred: boolean,
    accessToken: AccessTokenPayload,
    listId?: string,
    listIndex?: number,
    expiresIn?: number
  ): Promise<W3CVcIssuer> {
    this.logger.log(`Generating VcIssuer for ${issuerUri}`);
    if (!Array.isArray(vcTypes)) {
      vcTypes = [VERIFIABLE_ATTESTATION_TYPE, VERIFIABLE_CREDENTIAL_TYPE, vcTypes];
    }
    let kid: string;
    // EBSI CONFORMANCE TEST USE DID:KEY FOR NOW
    if (issuerDid.startsWith("did:key")) {
      kid = issuerDid.split("did:key:")[1];
    } else {
      kid = privateKeyJwk.kid || await calculateJwkThumbprint(privateKeyJwk);
    }
    const credentialSupported = [
      new CredentialSupportedBuilder().withFormat("jwt_vc").withTypes(vcTypes).build(),
    ];
    return new W3CVcIssuer(
      // Metadata
      {
        credential_issuer: issuerUri,
        credential_endpoint: issuerUri + "/credentials/",
        credentials_supported: credentialSupported
      }, this.didResolver,

      issuerDid,
      // Sign Callback
      async (_format, vc) => {
        const header = {
          typ: "JWT",
          alg: privateKeyJwk.alg || SUPPORTED_SIGNATURE_ALG,
          kid: `${issuerDid}#${kid}`
        };
        const keyLike = await importJWK(privateKeyJwk);
        return await new SignJWT(vc)
          .setProtectedHeader(header)
          .sign(keyLike);
      },
      // Nonce retrieval callback
      async (_id) => expectedCNonce,
      // Get VC Schema callback
      async (_types) => {
        return [
          {
            id: vcSchema,
            type: CREDENTIAL.schema_type
          }
        ]
      },
      // Get VC Data callback
      async (types, holder) => {
        if (isDeferred) {
          const subject = accessToken.isPreAuth ? accessToken.sub! : holder;
          const code = await this.registerDeferredVc(
            issuerUri,
            subject,
            this.getVcSpecificType(vcTypes as string[]),
            accessToken.pin
          );
          return {
            deferredCode: await this.generateAcceptanceToken(
              privateKeyJwk,
              kid,
              code,
              this.getVcSpecificType(vcTypes as string[]),
              issuerDid,
              holder,
              listId,
              listIndex,
            )
          };
        }
        const data = accessToken.isPreAuth ?
          await this.getCredentialData(
            this.getVcSpecificType(vcTypes as string[]),
            accessToken.sub!,
            issuerUri,
            accessToken.pin
          ) :
          await this.getCredentialData(
            this.getVcSpecificType(vcTypes as string[]),
            holder,
            issuerUri
          );
        const metadata = data.body._metadata ?? {};
        metadata.expiresInSeconds = metadata.expiresInSeconds ?? expiresIn;
        delete data.body._metadata;
        return { data: data.body, ...metadata }
      },
      // Resolve credential subject
      async (_, credentialSubject) => {
        return credentialSubject;
      }
    );
  }

  /**
   * Generate an instance of W3CVcIssuer that is defined to issue status VC
   * @param issuerUri The URI of the issuer
   * @param vcType The VC type that will be supported
   * @param issuerDid The DID of the issuer
   * @param privateKeyJwk The privateKey that will be used to sign the VC
   * @param vcSchema The schema identifier for the VC
   * @param getCredentialData Callback to generate credential subject data
   * @returns An instance of W3CVcIssuer
   */
  async buildVcIssuerForDirectIssuance(
    issuerUri: string,
    vcType: string[],
    issuerDid: string,
    privateKeyJwk: JWK,
    vcSchema: string,
    getCredentialData: GetCredentialData
  ) {
    const credentialSupported = [
      new CredentialSupportedBuilder().withFormat("jwt_vc").withTypes(vcType).build(),
    ];
    let kid: string;
    // EBSI CONFORMANCE TEST USE DID:KEY FOR NOW
    if (issuerDid.startsWith("did:key")) {
      kid = issuerDid.split("did:key:")[1];
    } else {
      kid = privateKeyJwk.kid || await calculateJwkThumbprint(privateKeyJwk);
    }
    return new W3CVcIssuer(
      {
        credential_issuer: issuerUri,
        credential_endpoint: issuerUri + "/credentials/",
        credentials_supported: credentialSupported
      },
      this.didResolver,
      issuerDid,
      async (_format, vc) => {
        const header = {
          typ: "JWT",
          alg: privateKeyJwk.alg || SUPPORTED_SIGNATURE_ALG,
          kid: `${issuerDid}#${kid}`
        };
        const vc_copy = JSON.parse(JSON.stringify(vc));
        if (vcType.includes(STATUS_LIST_2021_VC)) {
          ((vc_copy as JWTPayload).vc as
            W3CVerifiableCredential)["@context"].push(STATUS_LIST_CONTEXT);
        }
        const keyLike = await importJWK(privateKeyJwk);
        return await new SignJWT(vc_copy)
          .setProtectedHeader(header)
          .sign(keyLike);
      },
      async (_id) => "",
      async (_types) => {
        return [
          {
            id: vcSchema,
            type: CREDENTIAL.schema_type
          }
        ]
      },
      getCredentialData,
      async (_, credentialSubject) => {
        return credentialSubject;
      }
    );
  }

  private async generateAcceptanceToken(
    privateKeyJwk: JWK,
    kid: string,
    deferredCode: string,
    vcType: string,
    issuerDid: string,
    subject: string,
    listId?: string,
    listIndex?: number,
  ): Promise<string> {
    const header = {
      alg: privateKeyJwk.alg || SUPPORTED_SIGNATURE_ALG,
      kid: `${issuerDid}#${kid}`
    };
    const keyLike = await importJWK(privateKeyJwk);
    const jwt = await new SignJWT({
      code: deferredCode,
      vc_type: vcType,
      list_id: listId,
      list_index: listIndex,
    })
      .setProtectedHeader(header)
      .setSubject(subject)
      .sign(keyLike);
    return jwt;
  }

  private async registerDeferredVc(
    issuerUri: string,
    clientId: string,
    type: string,
    pin?: string,
  ): Promise<string> {
    let fetchResponse;
    const uri = removeSlash(issuerUri);
    const body: Record<string, any> = {
      client_id: clientId,
      vc_type: type
    };
    if (pin) {
      body.pin = pin;
    }
    try {
      fetchResponse = await fetch(
        `${uri}${CREDENTIAL.deferred_vc_register}`,
        {
          method: 'POST',
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify(body)
        }
      );
    } catch (error) {
      throw new InternalServerError(
        "Can't register VC for deferred flow",
        AuthzErrorCodes.SERVER_ERROR,
      );
    }
    if (!fetchResponse.ok) {
      this.logger.error(
        `POST to register VC for deferred flow failed with status ${fetchResponse.status}.
        Error ${fetchResponse.body}`
      );
      throw new InternalServerError(
        `Can't register VC for deferred flow"`,
        AuthzErrorCodes.SERVER_ERROR,
      );
    }
    const result = await fetchResponse.json() as string;
    return result;
  }

  /**
   * Allows a deferred VC code to be exchanged for the credential itself
   * @param code The code to exchange
   * @param issuerUri The URI of the issuer
   * @returns The data of the VC or a new deferred code
   */
  async exchangeCodeForVc(
    code: string,
    issuerUri: string
  ): Promise<IExchangeDeferredCodeResponse> {
    let fetchResponse;
    const uri = removeSlash(issuerUri);
    try {
      fetchResponse = await fetch(
        `${uri}${CREDENTIAL.deferred_vc_exchange}/${code}`,
      );
    } catch (error) {
      throw new InternalServerError(
        "Can't recover VC for deferred flow",
        AuthzErrorCodes.SERVER_ERROR,
      );
    }
    if (!fetchResponse.ok) {
      this.logger.error(
        `GET to recover VC for deferred flow failed with status ${fetchResponse.status}.
        Error ${fetchResponse.body}`
      );
      throw new InternalServerError(
        `Can't recover VC for deferred flow"`,
        AuthzErrorCodes.SERVER_ERROR,
      );
    }
    return await fetchResponse.json() as IExchangeDeferredCodeResponse;
  }

  async getCredentialData(
    vcType: string,
    clientId: string,
    issuerUri: string,
    pin?: string,
  ): Promise<CredentialDataResponse> {
    try {
      const data = {
        vc_type: vcType,
        user_id: clientId
      } as Record<string, string>;
      if (pin) {
        this.logger.log(`Pin "${pin} included in external-data request"`);
        data.pin = pin;
      }
      const params = new URLSearchParams(Object.entries(data)).toString();
      const fetchResponse = await fetch(
        `${issuerUri}${CREDENTIAL.vc_data_endpoint}?${params}`,
        {
          signal: AbortSignal.timeout(20 * 1000)
        }
      );
      if (fetchResponse.status != 200) {
        this.logger.error(
          `An error ocurred requesting VC data: ${fetchResponse.statusText}`
        );
        throw new HttpError(
          500,
          AuthzErrorCodes.SERVER_ERROR,
          `Error retrieving VC data`
        );
      }
      if (fetchResponse.headers.get("Content-Type") != "application/json" &&
        fetchResponse.headers.get("content-type") != "application/json") {
        this.logger.error(`VC Data received not in JSON format`);
        throw new HttpError(
          500,
          AuthzErrorCodes.SERVER_ERROR,
          `Error retrieving VC data`
        );
      }
      return await fetchResponse.json() as CredentialDataResponse;
    } catch (error: any) {
      if (error instanceof HttpError) {
        throw error;
      }
      this.logger.error(`GET CREDENTIAL DATA ERROR: ${error.message}`)
      throw new HttpError(
        500,
        AuthzErrorCodes.SERVER_ERROR,
        "Error retrieving VC data"
      );
    }
  }

  /**
   * Given an access token allows to obtain the type of credential to which it relates.
   * @param token The access token (JWT) in object format
   * @returns The credential types
   */
  getVcTypesFromAccessToken(token: AccessTokenPayload): string[] {
    if (!token.vcType) {
      throw new HttpError(
        BearerTokenErrorCodes.INVALID_TOKEN.httpStatus,
        BearerTokenErrorCodes.INVALID_TOKEN.code,
        "The token received is invalid",
      )
    }
    return [
      VERIFIABLE_ATTESTATION_TYPE,
      VERIFIABLE_CREDENTIAL_TYPE,
      token.vcType
    ];
  }

  /**
   * Allow to compare two arrays to determine if they contains the same data
   * @param arr1 One of the arrays to compare
   * @param arr2 One of the arrays to compare
   * @returns True if both array contains the same element and have the same length
   */
  arraysContainSameStrings(arr1: string[], arr2: string[]): boolean {
    if (arr1.length !== arr2.length) {
      return false;
    }
    return arr1.every((item) => arr2.includes(item));
  }

  /**
   * Allows to get the credential type apart from
   *  VerifiableAttestation and VerifiableCredential
   * @param types All the types of the credential
   * @returns A single type of a credential
   */
  getVcSpecificType(types: string[]): string {
    const result = types.find((type) => {
      return type !== VERIFIABLE_ATTESTATION_TYPE &&
        type !== VERIFIABLE_CREDENTIAL_TYPE
    });
    if (!result) {
      throw new HttpError(
        CredentialErrorCodes.UNSUPPROTED_CREDENTIAL_TYPE.httpStatus,
        CredentialErrorCodes.UNSUPPROTED_CREDENTIAL_TYPE.code,
        `Types ${types} are not supported`
      );
    }
    return result;
  }

  getIssuerOfControlProof(controlProof: BaseControlProof): string {
    const proof = ControlProof.fromJSON(controlProof);
    return proof.getAssociatedIdentifier();
  }
}
