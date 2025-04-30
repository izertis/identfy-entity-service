import { calculateJwkThumbprint } from 'jose';
import fetch from "node-fetch";
import {Response} from "node-fetch";
import { keccak256 } from 'ethereumjs-util';
import BigNumber from "bignumber.js";
import Logger from "src/shared/classes/logger.js";
import {FetchError} from 'src/shared/classes/error/internalerror.js';
import {
  SignatureInputInformation,
  keysBackend
} from 'src/shared/utils/functions/auth.utils.js';
import {EBSI} from 'src/shared/config/configuration.js';
import {
  RawTransactionWithSignature,
  UnsignedTransaction
} from 'src/shared/types/transaction.types.js';
import {
  SignatureProvider
} from 'src/shared/classes/signature_provider/index.js';
import {PublicKeyFormat} from 'src/shared/types/keys.type.js';
import {decodeToken} from 'src/shared/utils/jwt.utils.js';
import {CredentialJWt} from 'src/shared/types/credential_jwt.types.js';
import {stringToHex} from 'src/shared/utils/string.utils.js';
import {
  generateRandomHash,
  generateSha256HashFromString
} from 'src/shared/utils/crypto.utils.js';
import { Common } from "@ethereumjs/common";
import { LegacyTransaction } from "@ethereumjs/tx";
import { SigningKey } from "ethers";
import { RLP } from '@ethereumjs/rlp';
import { computeAddress } from "ethers";
import Web3 from "web3";
import {IssuerType} from 'src/shared/types/ebsi.types.js';
import {wait} from 'src/shared/utils/time.utils.js';

const logger = new Logger();

export interface EbsiSendTransactionResponse {
  jsonrpc: string,
  id: number,
  result: string
}

export interface EbsiTransaction extends UnsignedTransaction, Omit<RawTransactionWithSignature, 'raw'> {
  blockHash: string | null,
  blockNumber: string | null,
  hash: string,
  input: string,
  transactionIndex: string | null,
  type: string
}
export function normalizeSignatureS(sHex: string): string {
  const ss = new BigNumber(sHex, 16);
  const SECP256K1_CURVE_ORDER = new BigNumber(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
  );
  // check if s is in the upper range (s > n / 2)
  let normalizedS;
  const halfCurveOrder = SECP256K1_CURVE_ORDER.dividedBy(2);
  if (ss.isGreaterThan(halfCurveOrder)) {
    normalizedS = SECP256K1_CURVE_ORDER.minus(ss);
  } else {
    normalizedS = ss;
  }

  return `${normalizedS.toString(16).padStart(64, "0")}`;
}

export class EbsiRpcManager {
  async sendTransaction(
    transaction: RawTransactionWithSignature,
    unsignedTransaction: UnsignedTransaction,
    accessToken: string,
    endpoint: string
  ): Promise<string> {
    let response;
    try {
      response = await fetch(endpoint, {
        method: 'POST',
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'sendSignedTransaction',
          id: 1,
          params: [
            {
              protocol: 'eth',
              unsignedTransaction: {
                from: unsignedTransaction.from,
                to: unsignedTransaction.to,
                data: unsignedTransaction.data,
                nonce: unsignedTransaction.nonce,
                chainId: unsignedTransaction.chainId,
                gasLimit: unsignedTransaction.gasLimit,
                gasPrice: unsignedTransaction.gasPrice,
                value: unsignedTransaction.value
              },
              r: transaction.r,
              s: transaction.s,
              v: '0x' + transaction.v.toString(16),
              signedRawTransaction: transaction.raw
            }
          ]
        }),
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          Authorization: `Bearer ${accessToken}`
        }
      });
    } catch (e: any) {
      throw new FetchError(`Can't send transaction to EBSI API: ${e}`);
    }
    const data = await response.json() as EbsiSendTransactionResponse;
    if (!data.result) {
      throw new FetchError(
        `An error occured during sendSignedTransaction execution: ${JSON.stringify(data, null, " ")}`
      );
    }
    return data.result
  }

  private async manageTransaction(
    accessToken: string,
    requestBody: Record<string, any>,
    method: string,
    keys_256k1: SignatureInputInformation,
    url?: string
  ) {
    const urlToUse = url ?? EBSI.DID_REGISTRY_RPC_ENDPOINT;
    let response: Response;
    try {
      response = await fetch(urlToUse, {
        method: 'POST',
        body: JSON.stringify({
          jsonrpc: '2.0',
          method,
          params: [requestBody]
        }),
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          Authorization: `Bearer ${accessToken}`
        }
      });
    } catch (e: any) {
      throw new FetchError(`Can't recover transaction from EBSI API ${e}`);
    }
    const fetchResult: any = (await response.json());
    if (!fetchResult.result) {
      throw new FetchError(
        `An error occured during ${method} execution: ${JSON.stringify(fetchResult, null, " ")}`);
    }
    const unsignedTransaction = fetchResult.result;

    const signatureProvider = SignatureProvider.generateProvider(
      keys_256k1.format,
      keys_256k1.type,
      keys_256k1.value
    );
    const pubKeyHex = await signatureProvider.getPublicKey(PublicKeyFormat.HEX);
    const chainId = parseInt(unsignedTransaction.chainId, 16);
    const common = Common.custom({
      networkId: chainId,
      chainId: chainId
    });
    const msg = new LegacyTransaction(unsignedTransaction, { common: common });
    const hash = msg.getMessageToSign()
    const hash2 = Buffer.from(RLP.encode((hash)));

    const tx = (await signatureProvider.signRaw(
      hash2,
      "hex",
      "keccak256"
    ));
    const r = tx.slice(0, 64).replace(/^0+/, '');
    const s = tx.slice(64, 128).replace(/^0+/, '');
    const v = (parseInt(unsignedTransaction.chainId, 16) * 2) + 35
    const signature = {
      "r": "0x" + r, "s": "0x" + s, "v": v
    };

    signature.s = "0x" + normalizeSignatureS(s);
    let compareV = signature.v;
    try {
      let recoveryP0 = SigningKey.recoverPublicKey(keccak256(hash2), { r: signature.r, s: signature.s, yParity: 0 });
      // recoveryP0 = recoveryP0.startsWith("0x") ? recoveryP0.substring(2) : recoveryP0;
      compareV = recoveryP0 === pubKeyHex ? signature.v : compareV;
    } catch {
      logger.log("V in signature not match");
    }
    try {
      let recoveryP1 = SigningKey.recoverPublicKey(keccak256(hash2), { r: signature.r, s: signature.s, yParity: 1 });
      // recoveryP1 = recoveryP1.startsWith("0x") ? recoveryP1.substring(2) : recoveryP1;
      compareV = recoveryP1 === pubKeyHex ? signature.v + 1 : compareV;
    } catch {
      logger.log("V+1 in signature not match");
    }
    signature.v = compareV;
    const txSignedElliptic = LegacyTransaction.fromTxData({ ...unsignedTransaction, ...signature }).serialize();

    return await this.sendTransaction(
      { "raw": Web3.utils.bytesToHex(txSignedElliptic), ...signature } as RawTransactionWithSignature,
      unsignedTransaction,
      accessToken,
      urlToUse
    );
  }

  async insertDidDocument(
    accessToken: string,
    did: string,
    url: string
  ): Promise<string> {
    const currentTime = Math.floor(Date.now() / 1000);
    const keys_256k1 = (await keysBackend(url, "secp256k1"));
    const signatureProvider = (await SignatureProvider.generateProvider(
      keys_256k1.format,
      keys_256k1.type,
      keys_256k1.value
    ));
    const publicJWK = await signatureProvider.getPublicKey(PublicKeyFormat.JWK);
    const thumbprint = await calculateJwkThumbprint(publicJWK);
    const pubKeyHex = await signatureProvider.getPublicKey(PublicKeyFormat.HEX);
    const pubK = pubKeyHex.startsWith("0x") ? pubKeyHex : "0x" + pubKeyHex;
    const address = computeAddress(pubK);
    return this.manageTransaction(
      accessToken,
      {
        from: address,
        did,
        baseDocument: JSON.stringify({
          '@context': [
            'https://www.w3.org/ns/did/v1',
            'https://w3id.org/security/suites/jws-2020/v1'
          ],
        }),
        vMethodId: thumbprint,
        publicKey: pubK,
        isSecp256k1: true,
        notBefore: currentTime,
        notAfter: currentTime + EBSI.MAX_TIME_DID_DOCUMENT_VERIFICATION_METHOD_IN_SECONDS
      },
      'insertDidDocument',
      keys_256k1
    );
  }

  async tirSetAttributeData(
    accesToken: string,
    did: string,
    url: string,
    credential: string
  ): Promise<string> {
    const keys_256k1 = (await keysBackend(url, "secp256k1"));
    const signatureProvider = (await SignatureProvider.generateProvider(
      keys_256k1.format,
      keys_256k1.type,
      keys_256k1.value
    ));
    const pubKey = await signatureProvider.getPublicKey(PublicKeyFormat.HEX);
    const pubK = pubKey.startsWith("0x") ? pubKey : "0x" + pubKey;
    const address = computeAddress(pubK);
    const credentialDeserialized = decodeToken(credential);
    const credentialPayload = credentialDeserialized.payload as CredentialJWt;
    let attributeId = credentialPayload.vc.credentialSubject.reservedAttributeId
    attributeId = attributeId.startsWith("0x") ? attributeId : "0x" +attributeId;
    const attributeData = stringToHex(credential);
    return this.manageTransaction(
      accesToken,
      {
        from: address,
        did,
        attributeId,
        attributeData,
      },
      'setAttributeData',
      keys_256k1,
      EBSI.TI_REGISTRY_RPC_ENDPOINT
    );
  }

  async tirAddIssuerProxy(
    accessToken: string,
    did: string,
    url: string,
    prefix: string,
    testSuffix: string,
    headers: Record<string, any> = {}
  ): Promise<{ txId: string, proxyId: string }> {
    const keys_256k1 = (await keysBackend(url, "secp256k1"));
    const signatureProvider = SignatureProvider.generateProvider(
      keys_256k1.format,
      keys_256k1.type,
      keys_256k1.value
    );
    const pubKey = await signatureProvider.getPublicKey(PublicKeyFormat.HEX);
    const pubK = pubKey.startsWith("0x") ? pubKey : "0x" + pubKey;
    const address = computeAddress(pubK);
    const proxyData = JSON.stringify({ "prefix": prefix, "headers": headers, "testSuffix": testSuffix });

    return {
      txId: await this.manageTransaction(
        accessToken,
        {
          from: address,
          did,
          proxyData,
        },
        'addIssuerProxy',
        keys_256k1,
        EBSI.TI_REGISTRY_RPC_ENDPOINT
      ),
      proxyId: generateSha256HashFromString(proxyData)
    }
  }

  async tirInserIssuer(
    accessToken: string,
    did: string,
    issuerType: IssuerType,
    taoDid: string,
    attributeIdTao: string,
    url: string,
  ): Promise<{ txId: string, hash: string }> {
    const keys_256k1 = (await keysBackend(url, "secp256k1"));
    const signatureProvider = SignatureProvider.generateProvider(
      keys_256k1.format,
      keys_256k1.type,
      keys_256k1.value
    );
    const pubKey = await signatureProvider.getPublicKey(PublicKeyFormat.HEX);
    const pubK = pubKey.startsWith("0x") ? pubKey : "0x" + pubKey;
    const address = computeAddress(pubK);
    const hash = "0x" + generateRandomHash();
    return {
      txId: await this.manageTransaction(
        accessToken,
        {
          from: address,
          did,
          revisionId: hash, // TODO V5: This has changed from version 4 to 5. In 5 it's revisionId
          issuerType: issuerType.value,
          taoDid,
          attributeIdTao: attributeIdTao // TODOB V5: This have changed from version 4 to 5,  In 5 it's attributeIdTao
        },
        'setAttributeMetadata',
        keys_256k1,
        EBSI.TI_REGISTRY_RPC_ENDPOINT
      ),
      hash
    }
  }

  async revokeAccreditation(
    accesToken: string,
    did: string,
    taoDid: string,
    taoAttributeId: string,
    revisionId: string,
    url: string,
  ): Promise<{ txId: string, hash: string }> {
    const keys_256k1 = (await keysBackend(url, "secp256k1"));
    const signatureProvider = SignatureProvider.generateProvider(
      keys_256k1.format,
      keys_256k1.type,
      keys_256k1.value
    );
    const pubKey = await signatureProvider.getPublicKey(PublicKeyFormat.HEX);
    const pubK = pubKey.startsWith("0x") ? pubKey : "0x" + pubKey;
    const address = computeAddress(pubK);

    let hash = revisionId;
    if (!hash.startsWith("0x")) {
      hash = "0x" + hash;
    }
    return {
      txId: await this.manageTransaction(
        accesToken,
        {
          from: address,
          did,
          revisionId: hash, // TODO: This has changed from version 4 to 5. In 5 it's revisionId
          issuerType: IssuerType.REVOKED.value,
          taoDid,
          attributeIdTao: taoAttributeId // TODO: This have changed from version 4 to 5
        },
        'setAttributeMetadata',
        keys_256k1,
        EBSI.TI_REGISTRY_RPC_ENDPOINT
      ),
      hash
    }
  }

  async addVerificationMethod(
    accessToken: string,
    did: string,
    url: string,
  ): Promise<string> {
    const keys_256k1 = (await keysBackend(url, "secp256k1"));
    const keys_256r1 = (await keysBackend(url, "secp256r1"));
    const signatureProvider = SignatureProvider.generateProvider(
      keys_256k1.format,
      keys_256k1.type,
      keys_256k1.value
    );
    const pubKeyHex256k = await signatureProvider.getPublicKey(PublicKeyFormat.HEX);
    const pubK = pubKeyHex256k.startsWith("0x") ? pubKeyHex256k : "0x" + pubKeyHex256k;
    const address = computeAddress(pubK);
    const signatureProvider256r1 = SignatureProvider.generateProvider(
      keys_256r1.format,
      keys_256r1.type,
      keys_256r1.value
    );
    const publicJWK_256r1 = await signatureProvider256r1.getPublicKey(PublicKeyFormat.JWK);
    const thumbprint = await calculateJwkThumbprint(publicJWK_256r1);
    const pubKey = stringToHex(JSON.stringify(publicJWK_256r1));

    return this.manageTransaction(
      accessToken,
      {
        from: address,
        did,
        vMethodId: thumbprint,
        isSecp256k1: false,//isSecp256k1,
        publicKey: pubKey,
      },
      'addVerificationMethod',
      keys_256k1
    );
  }

  async addVerificationRelationship(
    accesToken: string,
    did: string,
    name: string,
    signature: SignatureProvider,
    keys_256k1: SignatureInputInformation,
    vMethodId: string,
  ): Promise<string> {
    const currentTime = Math.floor(Date.now() / 1000);
    const pubKeyHex256k = await signature.getPublicKey(PublicKeyFormat.HEX);
    const pubK = pubKeyHex256k.startsWith("0x") ? pubKeyHex256k : "0x" + pubKeyHex256k;
    const address = computeAddress(pubK);
    return this.manageTransaction(
      accesToken,
      {
        from: address,
        did,
        name,
        vMethodId,
        notBefore: currentTime,
        notAfter: currentTime + EBSI.MAX_TIME_DID_DOCUMENT_VERIFICATION_METHOD_IN_SECONDS
      },
      'addVerificationRelationship',
      keys_256k1
    );
  }

  async waitForTxToBeMined(txId: string) {
    while (true) {
      const tx = await this.getTx(txId);
      if (tx.blockHash) {
        break;
      }
      await wait(250)
    }
  }

  async getTx(txId: string): Promise<EbsiTransaction> {
    let response;
    try {
      response = await fetch(EBSI.BESU_RPC_ENDPOINT, {
        method: 'POST',
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'eth_getTransactionByHash',
          params: [txId],
          id: 1
        }),
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        }
      });
    } catch (e: any) {
      throw new FetchError(`Can't recover transaction from EBSI BESU RPC: ${e}`);
    }
    if (!response.ok) {
      throw new FetchError(`Fetch request failed with error ${JSON.stringify(response.body, null, " ")}`);
    }
    const jsonResponse: any = await response.json();
    if (!jsonResponse.result) {
      throw new FetchError(
        `An error occured during getTx execution: ${JSON.stringify(jsonResponse, null, " ")}`
      );
    }
    return jsonResponse.result;
  }

}
