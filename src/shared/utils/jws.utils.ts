import {
  JWK,
  JWTVerifyResult,
  decodeProtectedHeader,
  importJWK,
  jwtVerify
} from "jose";
import { JwsError } from "../classes/error/internalerror.js";

export async function verifyJWS(
  jws: string,
  keyResolve: (kid: string) => JWK
): Promise<JWTVerifyResult> {
  const protectedHeader = decodeProtectedHeader(jws);
  if (!protectedHeader.kid) {
    throw new JwsError('No "kid" parameter in JWS protected header');
  }
  const jwk = keyResolve(protectedHeader.kid);
  const publicKey = await importJWK(jwk);
  try {
    return await jwtVerify(jws, publicKey);
  } catch (e: any) {
    throw new JwsError('Signature verification failed');
  }
}