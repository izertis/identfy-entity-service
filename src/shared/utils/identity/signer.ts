import {jwkFromSecretKey} from '../jwk.utils.js';
import {Identity} from './identity.js';
import {HasDidUrl, isSameDidUrlOrDerived} from './has-did-url.js';

export class Signer implements HasDidUrl {
  constructor(
    private readonly identity: Identity,
    private secretKey: string,
    private curve: string,
  ) {}

  getDidUrl() {
    return this.identity.getDidUrl();
  }

  getCurve() {
    return this.curve;
  }

  getJwk(): any {
    return jwkFromSecretKey(this.secretKey, this.curve);
  }

  isMeOrDerived(other: string | HasDidUrl) {
    return isSameDidUrlOrDerived(this, other);
  }
}
