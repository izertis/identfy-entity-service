import { Identity } from "../../identity/identity";
import { jwkFromSecretKey } from "../../jwk.utils.js";
import EthereumHDKey from "ethereumjs-wallet/dist/hdkey";
import { util as EbsiResolverUtil } from "@cef-ebsi/key-did-resolver"
import elliptic from 'elliptic';
import { Signer } from "../../identity/signer";
const { ec: EC } = elliptic;

export const DIDKEY_DID_METHOD = "key";

const DIDKEY_IDENTITY_CURVE = "p256";

export class DidKeyIdentity extends Identity {

    constructor(
        private readonly did: string
    ) {
        super();
    }

    static fromRootIdentity(rootIdentity: EthereumHDKey): DidKeyIdentity {
        const seed = DidKeyIdentity.seedFromRootIdentity(rootIdentity);
        const keyPair = DidKeyIdentity.keyPairFromSeed(seed);
        const secretKey = keyPair.getPrivate('hex');
        const jwk = jwkFromSecretKey(secretKey, DIDKEY_IDENTITY_CURVE);
        const did = EbsiResolverUtil.createDid(jwk);
        return new DidKeyIdentity(did);
    }

    static fromDidUrl(didUrl: string) {
        const did = didUrl.split("?")[0];
        return new DidKeyIdentity(did);
    }

    static seedFromRootIdentity(rootIdentity: EthereumHDKey): Buffer {
        return rootIdentity.getWallet().getPrivateKey();
    }

    static keyPairFromSeed(seed: Buffer): elliptic.ec.KeyPair {
        return (new EC(DIDKEY_IDENTITY_CURVE)).keyFromPrivate(seed);
    }

    getDid() {
        return this.did;
    }

    getDidUrl() {
        return this.getDid();
    }

    getSigner(rootIdentity: EthereumHDKey): Signer {
        const seed = DidKeyIdentity.seedFromRootIdentity(rootIdentity);
        const keyPair = DidKeyIdentity.keyPairFromSeed(seed);
        const secretKey = keyPair.getPrivate('hex');
        return new Signer(this, secretKey, DIDKEY_IDENTITY_CURVE);
    }

}