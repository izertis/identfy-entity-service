import {VerificationMethod} from 'did-resolver';
import {publicJwkToDer} from '../../../shared/utils/der.utils.js';

export interface VerificationMethodTypeResolver {
  toDer(verificationMethod: VerificationMethod): Buffer;
}

export class JsonWebKey2020Resolutor implements VerificationMethodTypeResolver {
  static IDENTIFIER: string = 'JsonWebKey2020';
  toDer(verificationMethod: VerificationMethod): Buffer {
    if (!verificationMethod.publicKeyJwk) {
      throw new Error('Invalid format for JsonWebKey2020'); // TODO: Custom error
    }
    return publicJwkToDer(verificationMethod.publicKeyJwk!);
  }
}
