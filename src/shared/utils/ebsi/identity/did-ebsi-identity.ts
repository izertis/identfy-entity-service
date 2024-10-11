import { Identity } from "../../identity/identity";
import EthereumHDKey from "ethereumjs-wallet/dist/hdkey";
import { Signer } from "../../identity/signer";

export const DIDEBSI_DID_METHOD = "ebsi";

export class DidEbsiIdentity extends Identity {

  constructor(
    private readonly did: string
  ) {
    super();
  }

  static fromDidUrl(didUrl: string) {
    const did = didUrl.split("?")[0];
    return new DidEbsiIdentity(did);
  }

  getDid() {
    return this.did;
  }

  getDidUrl() {
    return this.getDid();
  }

  getSigner(rootIdentity: EthereumHDKey): Signer {
    throw new Error("DID EBSI has not an associated signed")
  }

}