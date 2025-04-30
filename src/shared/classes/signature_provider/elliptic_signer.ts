import {JWK} from "jose";
import {PublicKeyFormat} from "src/shared/types/keys.type.js";
import {SignKey} from "./signkey.js";
import pkg from 'elliptic';
const {ec} = pkg;

export class EllipticSignatureProvider extends SignKey {
  getPublicKey(format: PublicKeyFormat.JWK): JWK;
  getPublicKey(format: PublicKeyFormat.HEX): string;
  getPublicKey(format: PublicKeyFormat): JWK | string {
    switch (format) {
      case PublicKeyFormat.JWK:
        return {
          x: this.keysData.x,
          y: this.keysData.y,
          kty: 'EC',
          crv: this.keysData.crv
        };
      case PublicKeyFormat.HEX:
        const xBuffer = Buffer.from(this.keysData.x!, "base64url");
        const yBuffer = Buffer.from(this.keysData.y!, "base64url");
        return '0x04' + xBuffer.toString('hex') + yBuffer.toString('hex')
    }
  }

  sign(data: Buffer, encoding: BufferEncoding): string {
    const EC = new ec(this._keysType === 'secp256k1' ? 'secp256k1' : 'p256');
    const privateKey = EC.keyFromPrivate(Buffer.from(this.keysData.d!, 'base64url'));
    const signature = privateKey.sign(data, {canonical: true});
    const r = signature.r.toArrayLike(Buffer, 'be', 32);
    const s = signature.s.toArrayLike(Buffer, 'be', 32);
    return Buffer.concat([r, s]).toString(encoding);
  }

}
