import { jwkFromSecretKey } from "../jwk.utils";
import { Identity } from "./identity";
import { HasDidUrl } from "./has-did-url";

export class Signer implements HasDidUrl{

    constructor(
        private readonly identity: Identity,
        private secretKey: string,
        private curve: string
    ) { }

    getDidUrl() {
        return this.identity.getDidUrl();
    }

    getCurve() {
        return this.curve;
    }

    getJwk(): any {
        return jwkFromSecretKey(this.secretKey, this.curve);
    }
}