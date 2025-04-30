import {JWK} from 'jose';
import {UnsupportedKty} from '../classes/error/internalerror.js';

export function publicJwkToDer(key: JWK): Buffer {
  switch (key.kty) {
    case 'EC':
      return Buffer.concat([
        Buffer.from('04', 'hex'),
        Buffer.from(key.x!, 'base64url'),
        Buffer.from(key.y!, 'base64url'),
      ]);
    default:
      throw new UnsupportedKty('Unssuported kty');
  }
}
