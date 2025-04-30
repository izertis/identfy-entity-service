import {Signer} from './signer.js';
import {HasDidUrl, isSameDidUrlOrDerived} from './has-did-url.js';
import EthereumHDKey from 'ethereumjs-wallet/dist/hdkey.js';

export abstract class Identity implements HasDidUrl {
  abstract getDid(): string;

  abstract getDidUrl(): string;

  abstract isDerivable(): boolean;

  abstract deriveIdentity(derivationPath?: string): Identity;

  abstract getSigner(walletIdentity: EthereumHDKey.default): Signer;

  isMeOrDerived(other: string | HasDidUrl) {
    return isSameDidUrlOrDerived(this, other);
  }
}
