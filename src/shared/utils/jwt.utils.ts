import * as jwt from 'jsonwebtoken';

/**
 * Deserialize a JWT, which allows to obtain its header, payload and signature
 * @param jsonWebtoken The token to deserialize/decode
 * @returns The header, payload and signature of the token provided
 * @throws if the token provided is invalid for decoding
 */
export function decodeToken(jsonWebtoken: string): jwt.Jwt {
  const result = jwt.decode(jsonWebtoken, {complete: true});
  if (!result) {
    throw new Error('Invalid JWT for decoding');
  }
  return result;
}

export function algFromCurve(curve: string) {
  if (curve === 'P-256' || curve === 'p256') {
    return 'ES256';
  } else if (curve === 'secp256k1') {
    return 'ES256K';
  } else {
    throw new Error('Unsupported curve: ' + curve);
  }
}
