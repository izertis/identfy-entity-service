import { EnumType } from "../classes/enum.js";

export type IssuerTypesKeys = "RootTao" | "Tao" | "TrustedIssuer" | "Revoked";

export class IssuerType extends EnumType<number> {
  static readonly ROOT_TAO = new IssuerType("RootTao", 1);
  static readonly TAO = new IssuerType("Tao", 2);
  static readonly TRUSTED_ISSUER = new IssuerType("TrustedIssuer", 3);
  static readonly REVOKED = new IssuerType("Revoked", 4);

  static fromKey(key: IssuerTypesKeys) {
    switch (key) {
      case "RootTao":
        return IssuerType.ROOT_TAO;
      case "Tao":
        return IssuerType.TAO;
      case "TrustedIssuer":
        return IssuerType.TRUSTED_ISSUER;
      case "Revoked":
        return IssuerType.REVOKED;
      default:
        throw new Error("Unrecognized issuer type");
    }
  }

  static fromValue(value: number) {
    switch (value) {
      case 1:
        return IssuerType.ROOT_TAO;
      case 2:
        return IssuerType.TAO;
      case 3:
        return IssuerType.TRUSTED_ISSUER;
      case 4:
        return IssuerType.REVOKED;
      default:
        throw new Error("Unrecognized issuer type");
    }
  }
}