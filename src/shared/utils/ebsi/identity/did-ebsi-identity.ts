import EthereumHDKey from 'ethereumjs-wallet/dist/hdkey.js';
import {Identity} from '../../identity/identity.js';
import {Signer} from '../../identity/signer.js';

export const DIDEBSI_DID_METHOD = 'ebsi';

export class DidEbsiIdentity extends Identity {
  constructor(private readonly did: string) {
    super();
  }

  static fromDidUrl(didUrl: string) {
    const did = didUrl.split('?')[0];
    return new DidEbsiIdentity(did);
  }

  getDid() {
    return this.did;
  }

  getDidUrl() {
    return this.getDid();
  }

  isDerivable(): boolean {
    return false;
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  deriveIdentity(derivationPath?: string): Identity {
    throw new Error('Did EBSI is not derivable');
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  getSigner(rootIdentity: EthereumHDKey.default): Signer {
    throw new Error('DID EBSI has not an associated signed');
  }
}
