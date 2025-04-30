import { JWK } from "jose";
import {
  KeyData,
  KeyFormat,
  KeysType,
  PublicKeyFormat
} from "../../types/keys.type.js";

export abstract class SignKey {
  constructor(
    protected format: KeyFormat.JWK,
    protected keysData: KeyData,
    protected _keysType: KeysType
  ) {

  }

  get keysType() {
    return this._keysType
  }

  abstract getPublicKey(format: PublicKeyFormat.JWK): JWK;
  abstract getPublicKey(format: PublicKeyFormat.HEX): string;
  abstract getPublicKey(format: PublicKeyFormat): JWK | string;

  abstract sign(
    data: Buffer,
    encoding: BufferEncoding,
  ): string;

}