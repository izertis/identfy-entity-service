import { JWK } from "jose";

export type KeysType = "secp256k1" | "secp256r1";
export type KeyData = JWK;
export enum KeyFormat {
  JWK = 'jwk',
}
export enum PublicKeyFormat {
  JWK = 'jwk',
  HEX = 'hex',
}
