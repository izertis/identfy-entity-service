import { JWK, JWTHeaderParameters, JWTPayload } from "jose";
import { toBase64Url } from "../../utils/base64url.utils.js";
import { SupportedJwaAlgs } from "../../types/jwa.types.js";
import { UnsupportedJWA, UnsupportedKty } from "../error/internalerror.js";
import { HashFunctions } from "../../types/hash_functions.js";
import { HasherFactory } from "../hasher.factory.js";
import { SignKey } from "./signkey.js";
import { KeyData, KeyFormat, KeysType, PublicKeyFormat } from "../../types/keys.type.js";
import { EllipticSignatureProvider } from "./elliptic_signer.js";

export class SignatureProvider {
  private constructor(private signKey: SignKey) { }

  static generateProvider(
    format: KeyFormat,
    keyType: KeysType,
    keyData: KeyData
  ): SignatureProvider {
    switch (keyType) {
      case "secp256k1":
      case "secp256r1":
        if (format === KeyFormat.JWK) {
          return new SignatureProvider(new EllipticSignatureProvider(
            format,
            keyData,
            keyType
          ));
        }
        throw new Error("Invalid Keys Format provided") // TODO: CUSTOM ERROR -> INTERNAL SERVER ERROR
    }
  }

  private getHasherForJwa(alg: string): HashFunctions {
    if (!SupportedJwaAlgs.includes(alg as any)) {
      throw new UnsupportedJWA('Unssuported Header alg param');
    }
    const {kty, hasher} = JwaTable[alg as (typeof SupportedJwaAlgs)[number]];
    if (kty !== this.signKey.keysType) {
      throw new UnsupportedKty('Invalid kty for header alg');
    }
    return hasher;
  }

  async signJwt(
    header: JWTHeaderParameters,
    payload: JWTPayload,
  ): Promise<string> {
    const headerBase64Url = toBase64Url(JSON.stringify(header));
    const payloadBase64Url = toBase64Url(JSON.stringify(payload));
    const content = `${headerBase64Url}.${payloadBase64Url}`;
    const hasher = this.getHasherForJwa(header.alg);
    const signature = await this.signRaw(
      Buffer.from(content),
      'base64url',
      hasher,
    );
    return `${headerBase64Url}.${payloadBase64Url}.${signature}`;
  }

  async signRaw(
    data: Buffer,
    encoding: BufferEncoding,
    hashAlg: HashFunctions,
  ): Promise<string> {
    const hasher = new HasherFactory().generateHasher(hashAlg);
    const hash = hasher.hash(data);
    return await this.signKey.sign(hash, encoding);
  }

  getPublicKey(format: PublicKeyFormat.JWK): JWK;
  getPublicKey(format: PublicKeyFormat.HEX): string;
  getPublicKey(format: PublicKeyFormat): JWK | string {
    return this.signKey.getPublicKey(format);
  }
}

const JwaTable: Record<
  (typeof SupportedJwaAlgs)[number],
  {kty: KeysType; hasher: HashFunctions}
> = {
  ES256: {
    kty: 'secp256r1',
    hasher: 'sha256',
  },
  ES256K: {
    kty: 'secp256k1',
    hasher: 'sha256',
  },
};
