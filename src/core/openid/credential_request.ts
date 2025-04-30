import fetch from "node-fetch";
import { CredentialResponse, TokenResponse } from "openid-lib";
import {
  ExecutionFailed,
  FetchError
} from "../../shared/classes/error/internalerror.js";
import {
  SignatureProvider
} from "../../shared/classes/signature_provider/index.js";
import { PublicKeyFormat } from "../../shared/types/keys.type.js";
import { crvToAlg } from "../../shared/utils/functions/auth.utils.js";
import { getKidFromDID } from "../../shared/utils/kid.utils.js";

export class CredentialRequest {
  constructor(private signer: SignatureProvider) { }

  async sendCredentialRequest(
    tokenResponse: TokenResponse,
    credentialEndpoint: string,
    audience: string,
    requestedCredential: string[],
    did: string,
    externalAddr: string,
    signerOptions?: {
      header_typ?: string
      subResolver?: () => string,
      kidPrefix?: string,
      omitIssuer?: boolean
    }
  ): Promise<CredentialResponse> {
    const pubKey = await this.signer.getPublicKey(PublicKeyFormat.JWK);

    const kid = await getKidFromDID(did, this.signer);

    const currentTime = Math.floor(Date.now() / 1000) - 5; // Clock Tolerance
    const jwt = await this.signer.signJwt(
      {
        typ: signerOptions?.header_typ,
        alg: await crvToAlg(pubKey.crv!),
        kid: kid
      },
      {
        aud: audience,
        nonce: tokenResponse.c_nonce,
        iss: externalAddr,
        iat: currentTime,
        nbf: currentTime,
        exp: currentTime + ((5 * 60))
      },
    );
    let response;
    try {
      response = await fetch(credentialEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${tokenResponse.access_token}`,
        },
        body: JSON.stringify({
          types: requestedCredential,
          // TODO: In the future, format should be dynamic
          format: 'jwt_vc',
          proof: {
            proof_type: 'jwt',
            jwt
          }
        })
      })
    } catch (e: unknown) {
      throw new FetchError(`Can't send credential request: ${e}`);
    }
    const credentialResponse = await response.json() as any;
    if (credentialResponse.error) {
      throw new ExecutionFailed(
        `Error received during credential request execution: ${
          credentialResponse.error_description
        }`
      )
    }
    return credentialResponse;
  }
}
