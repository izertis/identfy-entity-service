import { calculateJwkThumbprint } from "jose";
import {getResolver as keyDidResolver} from '@cef-ebsi/key-did-resolver';
import { getResolver as ebsiDidResolver } from "@cef-ebsi/ebsi-did-resolver";
import { EBSI } from "../config/configuration.js";
import { SignatureProvider } from "../classes/signature_provider/index.js";
import { PublicKeyFormat } from "../types/keys.type.js";
import { KeysFromDidResolver } from "../classes/did/resolver.js";
import {
  JsonWebKey2020Resolutor,
  KeysFromDidConfiguration
} from "../classes/did/index.js";
import { Resolver } from "did-resolver";

export async function getKidFromDID(
  did: string,
  signer: SignatureProvider
) {
  const pubKey = await signer.getPublicKey(PublicKeyFormat.JWK);
  let resolver: KeysFromDidResolver;
  const resolverResult = new KeysFromDidConfiguration("authentication")
    .withDidResolver(
      new Resolver({
        ...keyDidResolver(),
        ...ebsiDidResolver({
          registry: EBSI.did_registry,
        }),
      })
    )
    .withVerificationMethodTypeResolutor(
      JsonWebKey2020Resolutor.IDENTIFIER,
      new JsonWebKey2020Resolutor()
    )
    .generateInstance();
  resolver = resolverResult;
  let kid;
  try {
    const result = (await resolver.compareKeyWithDidDocumentsKeys(
      did,
      signer
    ));
    kid = result;
  } catch (e: any) {
    kid = did + "#" + await calculateJwkThumbprint(pubKey)
  }
  return kid;
}
