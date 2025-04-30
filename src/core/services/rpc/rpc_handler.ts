import {
  AddIssuerProxy,
  AddVerificationMethodInterface,
  AddVerificationRelationshipInterface,
  InsertTrustedIssuerInterface,
  OnboardDidInterface,
  RequestDeferredVcInterface,
  RequestVcInterface,
  RequestVcWithUriInterface,
  ResolveCredentialOfferInterface,
  RevokeAccreditationInterface,
  RpcMethod,
  SetTrustedIssuerDataInterface
} from "../../../shared/interfaces/rpc.interface.js";
// AuthServerMetadata
import { getScopeToUseForTIR } from "./rpc_utils.js";
import { calculateJwkThumbprint  } from 'jose';
import RpcSchema from "../../../shared/schemas/rpc.schemas.js";
import { RpcInvalidParams } from "../../../shared/classes/error/rpc.error.js";
import {
  SCOPE_TIR_WRITE,
  SCOPE_VP_DIDR_WRITE,
  SCOPE_VP_ONBOARD
} from "../../../shared/constants/ebsi.constants.js";
import { keysBackend } from "../../../shared/utils/functions/auth.utils.js";
import { EbsiRpcManager } from "../../ebsi/rpc_manager.js";
import {
  SignatureProvider
} from "../../../shared/classes/signature_provider/index.js";
import { PublicKeyFormat } from "../../../shared/types/keys.type.js";
import { IssuerType } from "../../../shared/types/ebsi.types.js";
import { AuthServerMetadata, CredentialOffer } from "openid-lib";
import {getAndCheckAuthMetadata} from "../../openid/metadata.js";
import { EBSI } from "../../../shared/config/configuration.js";
import { OpenId4VCI } from "../../openid/vc_request.js";
import { withVpToken } from "../../openid/authentication_request.js";

export class RpcHandler {
  constructor(private rpcSchema: RpcSchema) { }

  async onboardDid(rcpMethod: RpcMethod): Promise<string> {
    // We will request an Access Token for didr_invite scope to EBSI Auth Server
    // The token will be use as BEARER Token when interacting with the EBSI DID registry
    // This method will only register the DID, it won't update the document with the
    // verification methods
    const params = this.validateAgainstSchema<OnboardDidInterface>(
      rcpMethod,
      this.rpcSchema.onboardDidPayload
    );

    // Get Access token from EBSI
    const authMetadata = await getAndCheckAuthMetadata(
      EBSI.AUTH_EBSI_SERVER_URL,
      EBSI.DISCOVERY_PATH
    );

    // EBSI RPC API does not require authorization
    // Request openid didr_invite scope access_token
    const keys_256r1 = (await keysBackend(
      params.url,
      "secp256r1"
    ));
    const signatureProvider = SignatureProvider.generateProvider(
      keys_256r1.format,
      keys_256r1.type,
      keys_256r1.value
    );
    let tokenResponse = await processWithVp(
      signatureProvider,
      params.did,
      authMetadata,
      SCOPE_VP_ONBOARD,
      [params.vc]
    );
    // Interaction witH EBSI RPC API
    const rpcManager = new EbsiRpcManager();

    const txId = await rpcManager.insertDidDocument(
      tokenResponse.access_token,
      params.did,
      params.url,
    );

    await rpcManager.waitForTxToBeMined(txId);
    return txId;
  }

  async addVerificationMethod(rcpMethod: RpcMethod): Promise<string> {
    const params = this.validateAgainstSchema<AddVerificationMethodInterface>(
      rcpMethod,
      this.rpcSchema.addVerificationMethodPayload
    );
    // Get Access token from EBSI
    const authMetadata = await getAndCheckAuthMetadata(
      EBSI.AUTH_EBSI_SERVER_URL,
      EBSI.DISCOVERY_PATH
    );
    // EBSI RPC API does not require authorization
    // Request openid didr_write scope access_token
    const keys_256k1 = await keysBackend(params.url, "secp256k1");
    const signatureProvider = SignatureProvider.generateProvider(
      keys_256k1.format,
      keys_256k1.type,
      keys_256k1.value
    );
    let tokenResponse = await processWithVp(
      signatureProvider,
      params.did,
      authMetadata,
      SCOPE_VP_DIDR_WRITE,
      []
    );
    const rpcManager = new EbsiRpcManager();
    const txId = await rpcManager.addVerificationMethod(
      tokenResponse.access_token,
      params.did,
      params.url
    );
    await rpcManager.waitForTxToBeMined(txId);
    return txId;
  }

  async addVerificationRelationship(rcpMethod: RpcMethod): Promise<string> {
    const params = this.validateAgainstSchema<AddVerificationRelationshipInterface>(
      rcpMethod,
      this.rpcSchema.addVerificationRelationshipPayload
    );
    // Get Access token from EBSI
    const authMetadata = await getAndCheckAuthMetadata(
      EBSI.AUTH_EBSI_SERVER_URL,
      EBSI.DISCOVERY_PATH
    );
    // EBSI RPC API does not require authorization
    // Request openid didr_write scope access_token
    const keys_256k1 = await keysBackend(
      params.url,
      "secp256k1"
    );
    const signatureProvider = await SignatureProvider.generateProvider(
      keys_256k1.format,
      keys_256k1.type,
      keys_256k1.value
    );
    const keys_256r1 = (await keysBackend(params.url, "secp256r1"));
    const signatureProvider256r1 = SignatureProvider.generateProvider(
      keys_256r1.format,
      keys_256r1.type,
      keys_256r1.value
    );
    const publicJWK_256r1 = await signatureProvider256r1.getPublicKey(
      PublicKeyFormat.JWK
    );
    const thumbprint = await calculateJwkThumbprint(publicJWK_256r1);
    let tokenResponse = await processWithVp(
      signatureProvider,
      params.did,
      authMetadata,
      SCOPE_VP_DIDR_WRITE,
      []
    );
    const rpcManager = new EbsiRpcManager();
    const txId = await rpcManager.addVerificationRelationship(
      tokenResponse.access_token,
      params.did,
      params.name,
      signatureProvider,
      keys_256k1,
      thumbprint
    );
    await rpcManager.waitForTxToBeMined(txId);
    return txId;
  }

  async addTrustedIssuer(rcpMethod: RpcMethod) {
    const params = this.validateAgainstSchema<InsertTrustedIssuerInterface>(
      rcpMethod,
      this.rpcSchema.addTrustedIssuer
    );
    // Get Access token from EBSI
    const authMetadata = await getAndCheckAuthMetadata(
      EBSI.AUTH_EBSI_SERVER_URL,
      EBSI.DISCOVERY_PATH
    );
    // EBSI RPC API does not require authorization
    // Request openid didr_write scope access_token
    const keys_256r1 = (await keysBackend(params.url, "secp256r1"));
    const signatureProvider = SignatureProvider.generateProvider(
      keys_256r1.format,
      keys_256r1.type,
      keys_256r1.value
    );

    let tokenResponse = await processWithVp(
      signatureProvider,
      params.taoDid,
      authMetadata,
      SCOPE_TIR_WRITE,
      []
    );
    const rpcManager = new EbsiRpcManager();
    const { txId, hash } = await rpcManager.tirInserIssuer(
      tokenResponse.access_token,
      params.did,
      IssuerType.fromKey(params.issuerType),
      params.taoDid,
      params.taoAttributeId,
      params.url
    );
    await rpcManager.waitForTxToBeMined(txId);
    return hash;
  }

  async revokeAccreditation(rcpMethod: RpcMethod) {
    const params = this.validateAgainstSchema<RevokeAccreditationInterface>(
      rcpMethod,
      this.rpcSchema.revokeAccreditation
    );
    // Get Access token from EBSI
    const authMetadata = await getAndCheckAuthMetadata(
      EBSI.AUTH_EBSI_SERVER_URL,
      EBSI.DISCOVERY_PATH
    );
    const keys_256r1 = (await keysBackend(params.url, "secp256r1"));
    const signatureProvider = SignatureProvider.generateProvider(
      keys_256r1.format,
      keys_256r1.type,
      keys_256r1.value
    );
    // EBSI RPC API does not require authorization
    // Request openid didr_write scope access_token
    let tokenResponse = await processWithVp(
      signatureProvider,
      params.taoDid,
      authMetadata,
      SCOPE_TIR_WRITE,
      []
    );
    const rpcManager = new EbsiRpcManager();
    const { txId, hash } = await rpcManager.revokeAccreditation(
      tokenResponse.access_token,
      params.did,
      params.taoDid,
      params.taoAttributeId,
      params.revisionId,
      params.url
    );
    await rpcManager.waitForTxToBeMined(txId);
    return hash;
  }

  async setTrustedIssuerData(rcpMethod: RpcMethod) {
    const params = this.validateAgainstSchema<SetTrustedIssuerDataInterface>(
      rcpMethod,
      this.rpcSchema.setTrustedIssuerData
    );
    // Get Access token from EBSI
    const authMetadata = await getAndCheckAuthMetadata(
      EBSI.AUTH_EBSI_SERVER_URL,
      EBSI.DISCOVERY_PATH
    );
    // EBSI RPC API does not require authorization
    // Request openid didr_write scope access_token
    const keys_256r1 = (await keysBackend(params.url, "secp256r1"));
    const signatureProvider = SignatureProvider.generateProvider(
      keys_256r1.format,
      keys_256r1.type,
      keys_256r1.value
    );

    const scope = await getScopeToUseForTIR(params.did);
    let tokenResponse = await processWithVp(
      signatureProvider,
      params.did,
      authMetadata,
      scope,
      [params.vc]
    );
    const rpcManager = new EbsiRpcManager();
    const txId = await rpcManager.tirSetAttributeData(
      tokenResponse.access_token,
      params.did,
      params.url,
      params.vc
    );
    await rpcManager.waitForTxToBeMined(txId);
    return txId
  }

  async resolveCredentialOffer(rpcMethod: RpcMethod) {
    const params = this.validateAgainstSchema<ResolveCredentialOfferInterface>(
      rpcMethod,
      this.rpcSchema.resolveCredentialOffer
    );
    return await OpenId4VCI.resolveCredentialOffer(params.credentialOffer);
  }

  async requestVcWithURI(rpcMethod: RpcMethod) {
    const params = this.validateAgainstSchema<RequestVcWithUriInterface>(
      rpcMethod,
      this.rpcSchema.requestVcWithUri
    );
    // We are going to simulate we are working with a credential-offer
    // TODO: Analyze if we have to include the pre-code
    const credentialOffer: CredentialOffer = {
      credential_issuer: params.issuer,
      credentials: [
        {
          format: "jwt_vc",
          types: params.vcType,
        }
      ],
      grants: {
        authorization_code: {}
      }
    }
    const oid4vci = new OpenId4VCI();
    const credentialResponse = await oid4vci.requestVc(
      params.vcType,
      credentialOffer,
      params.externalAddr,
      params.did,
      params.pinCode,
      params.vcForVp,
      {
        header_typ: 'openid4vci-proof+jwt',
      },
    );
    return credentialResponse;
  }

  async requestVc(rpcMethod: RpcMethod) {
    const params = this.validateAgainstSchema<RequestVcInterface>(
      rpcMethod,
      this.rpcSchema.requestVc
    );
    const credentialOffer = await OpenId4VCI.resolveCredentialOffer(
      params.credentialOffer
    );
    const oid4vci = new OpenId4VCI();
    const credentialResponse = await oid4vci.requestVc(
      params.vcType,
      credentialOffer,
      params.externalAddr,
      params.did,
      params.pinCode,
      params.vcForVp,
      {
        header_typ: 'openid4vci-proof+jwt',
      },
    );
    return credentialResponse;
  }

  async requestDeferredVc(rpcMethod: RpcMethod) {
    const params = this.validateAgainstSchema<RequestDeferredVcInterface>(
      rpcMethod,
      this.rpcSchema.requestDeferredVc
    );
    const oid4vci = new OpenId4VCI();
    const credentialResponse = await oid4vci.requestDeferredVc(
      params.acceptanceToken,
      params.issuer,
    );
    return credentialResponse;
  }

  async addIssuerProxy(rpcMethod: RpcMethod) {
    const params = this.validateAgainstSchema<AddIssuerProxy>(
      rpcMethod,
      this.rpcSchema.addIssuerProxy
    );
    // Get Access token from EBSI
    const authMetadata = await getAndCheckAuthMetadata(
      EBSI.AUTH_EBSI_SERVER_URL,
      EBSI.DISCOVERY_PATH
    );
    // EBSI RPC API does not require authorization
    // Request openid tir_write scope access_token
    const keys_256r1 = (await keysBackend(params.url, "secp256r1"));
    const signatureProvider = SignatureProvider.generateProvider(
      keys_256r1.format,
      keys_256r1.type,
      keys_256r1.value
    );

    let tokenResponse = await processWithVp(
      signatureProvider,
      params.did,
      authMetadata,
      SCOPE_TIR_WRITE,
      []
    );
    const rpcManager = new EbsiRpcManager();
    const { txId, proxyId } = await rpcManager.tirAddIssuerProxy(
      tokenResponse.access_token,
      params.did,
      params.url,
      params.prefix,
      params.testSuffix,
      params.headers
    );
    await rpcManager.waitForTxToBeMined(txId);
    return proxyId;
  }

  private validateAgainstSchema<T>(
    rpcMethod: RpcMethod,
    schema: Zod.AnyZodObject
  ) {
    const result = schema.safeParse(rpcMethod.params);
    if (!result.success) {
      throw new RpcInvalidParams(`Invalid parameters provided: ${result.error}`);
    }
    return rpcMethod.params as T;
  }

}

async function processWithVp(
  signer: SignatureProvider,
  did: string,
  authMetadata: AuthServerMetadata,
  scope: string,
  crendentials: string[]
) {
  const authnRequest = withVpToken(signer, crendentials, did, authMetadata);

  const authnResponse = await authnRequest.sendRequest(scope);
  return authnResponse;
}
