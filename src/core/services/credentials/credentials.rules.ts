import { autoInjectable, singleton } from "tsyringe";
import {
  W3CVcIssuer,
  CredentialSupportedBuilder,
  BaseControlProof,
  ControlProof
} from "openid-lib";
import fetch from 'node-fetch';
import {
  JWK,
  JWTPayload,
  SignJWT,
  calculateJwkThumbprint,
  decodeJwt,
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
import { getResolver } from "@cef-ebsi/key-did-resolver";
import { CREDENTIAL, DEVELOPER } from "../../../shared/config/configuration.js";
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
import { AccessTokenPayload } from "../../../shared/interfaces/auth.interface.js";

@singleton()
@autoInjectable()
export default class CredentialsRules {
  keyResolver = getResolver();
  didResolver = new Resolver(this.keyResolver);

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
    accessToken: AccessTokenPayload
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
          alg: SUPPORTED_SIGNATURE_ALG,
          kid: `${issuerDid}#${kid}`
        };
        const keyLike = await importJWK(privateKeyJwk);
        return await new SignJWT(vc)
          .setProtectedHeader(header)
          .sign(keyLike);
      },
      async (_id) => expectedCNonce,
      async (_types) => {
        return [
          {
            id: vcSchema,
            type: CREDENTIAL.schema_type
          }
        ]
      },
      async (_types, holder) => {
        if (isDeferred) {
          const subject = accessToken.isPreAuth ? accessToken.sub! : holder;
          const code = await this.registerDeferredVc(
            issuerUri,
            subject,
            vcTypes[2],
            accessToken.pinCode
          );
          return {
            deferredCode: await this.generateAcceptanceToken(
              privateKeyJwk,
              kid,
              code,
              vcTypes[2],
              issuerDid,
              holder
            )
          };
        };
        const data = accessToken.isPreAuth ?
          await this.getCredentialData(
            vcTypes[2],
            accessToken.sub!,
            issuerUri
          ) :
          await this.getCredentialData(
            vcTypes[2],
            holder,
            issuerUri
          );
        this.logger.log(`Credential data received: ${data} of type ${typeof data}`);
        return { data };
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
  ): Promise<string> {
    const header = {
      alg: SUPPORTED_SIGNATURE_ALG,
      kid: `${issuerDid}#${kid}`
    };
    const keyLike = await importJWK(privateKeyJwk);
    const jwt = await new SignJWT({
      code: deferredCode,
      vc_type: vcType
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
      if (DEVELOPER.allow_empty_vc) {
        return "DEFAULT_CODE";
      }
      throw new InternalServerError(
        "Can't register VC for deferred flow",
        AuthzErrorCodes.SERVER_ERROR,
      );
    }
    if (!fetchResponse.ok) {
      if (DEVELOPER.allow_empty_vc) {
        return "DEFAULT_CODE";
      }
      this.logger.error(
        `POST to register VC for deferred flow failed with status ${fetchResponse.status}.
        Error ${fetchResponse.body}`
      );
      throw new InternalServerError(
        `Can't register VC for deferred flow"`,
        AuthzErrorCodes.SERVER_ERROR,
      );
    }
    return await fetchResponse.text();
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
      if (DEVELOPER.allow_empty_vc) {
        return { data: {} }
      }
      throw new InternalServerError(
        "Can't recover VC for deferred flow",
        AuthzErrorCodes.SERVER_ERROR,
      );
    }
    if (!fetchResponse.ok) {
      if (DEVELOPER.allow_empty_vc) {
        return { data: {} }
      }
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

  private async getCredentialData(
    vcType: string,
    clientId: string,
    issuerUri: string,
    pin?: string,
  ): Promise<Record<string, any>> {
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
        `${issuerUri}${CREDENTIAL.vc_data_endpoint}?${params}`
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
      return await fetchResponse.json() as Record<string, any>;
    } catch (error: any) {
      if (DEVELOPER.allow_empty_vc) {
        return {}
      }
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
      VERIFIABLE_CREDENTIAL_TYPE,
      VERIFIABLE_ATTESTATION_TYPE,
      token.vcType as string
    ]
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
    if (types.length !== 3) {
      throw new HttpError(
        CredentialErrorCodes.UNSUPPROTED_CREDENTIAL_TYPE.httpStatus,
        CredentialErrorCodes.UNSUPPROTED_CREDENTIAL_TYPE.code,
        `Types ${types} are not supported`
      );
    }
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
