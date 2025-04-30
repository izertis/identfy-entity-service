import querystring from "querystring";
import { v4 as uuidv4 } from 'uuid';
import { selectCredentials, verifyPresentationDefinition } from "./utils.js";
import fetch from "node-fetch";
import { calculateJwkThumbprint } from "jose";
import {
  AuthServerMetadata,
  DIFPresentationDefinition,
  TokenResponse
} from "openid-lib";
import {
  ExecutionFailed,
  FetchError
} from "../../shared/classes/error/internalerror.js";
import {
  SignatureProvider
} from "../../shared/classes/signature_provider/index.js";
import { PublicKeyFormat } from "../../shared/types/keys.type.js";
import { crvToAlg } from "../../shared/utils/functions/auth.utils.js";
import { getKidFromDID } from "src/shared/utils/kid.utils.js";

export function withVpToken(
  signer: SignatureProvider,
  credentials: string[],
  did: string,
  authMetadata: AuthServerMetadata
): AuthenticationRequestWithVpToken {
  return new AuthenticationRequestWithVpToken(
    signer,
    credentials,
    did,
    authMetadata
  );
}

export function withCode(
  signer: SignatureProvider,
  code: string,
  authMetadata: AuthServerMetadata
): AuthenticationRequestWithCode {
  return new AuthenticationRequestWithCode(signer, code, authMetadata);
}

export function withPreAuthCode(
  code: string,
  authMetadata: AuthServerMetadata
): AuthenticationRequestWithPreAuth {
  return new AuthenticationRequestWithPreAuth(code, authMetadata);
}

class AuthenticationRequestWithVpToken {
  constructor(
    private signer: SignatureProvider,
    private credentials: string[],
    private did: string,
    private authMetadata: AuthServerMetadata
  ) { }

  async sendRequest(scope: string): Promise<TokenResponse> {
    if (!this.authMetadata.presentation_definition_endpoint) {
      throw new ExecutionFailed(
        'Auth Metadata does not specify presentation definition endpoint'
      );
    }
    const presentationDefinition = await this.getPresentationDefinition(
      this.authMetadata.presentation_definition_endpoint,
      scope
    );
    return await this.sendVpTokenResponse(
      scope,
      presentationDefinition
    );
  }

  private async sendVpTokenResponse(
    scope: string,
    presentationDefinition: DIFPresentationDefinition
  ): Promise<TokenResponse> {
    verifyPresentationDefinition(presentationDefinition);
    const [submission, selectedCredentials] = selectCredentials(presentationDefinition, this.credentials);
    const pubKey = await this.signer.getPublicKey(PublicKeyFormat.JWK);
    const kid = await getKidFromDID(
      this.did,
      this.signer
    );
    const currentTime = Math.floor(Date.now() / 1000) - 5; // Clock Tolerance
    const vp_token = await this.signer.signJwt(
      {
        typ: "JWT",
        alg: await crvToAlg(pubKey.crv!),
        kid: kid
      },
      {
        aud: this.authMetadata.issuer,
        iss: this.did,
        nonce: uuidv4(),
        vp: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          id: uuidv4(),
          type: ['VerifiablePresentation'],
          holder: this.did,
          verifiableCredential: selectedCredentials
        },
        iat: currentTime,
        nbf: currentTime,
        exp: currentTime + ((5 * 60)),
        sub: this.did
      },


    );

    const body = querystring.stringify({
      grant_type: 'vp_token',
      scope: scope,
      vp_token: vp_token,
      presentation_submission: JSON.stringify(submission)
    });

    let fetchResponse;

    try {
      const response = await fetch(this.authMetadata.token_endpoint!, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'accept-charset': 'utf-8',
        },
        body,
      });

      fetchResponse = await response.json() as any;

    } catch (e: unknown) {
      throw new FetchError(`Can't send VP Token Response: ${e}`);
    }
    if (fetchResponse.error) {
      throw new ExecutionFailed(
        `Authentication process failed with error: ${JSON.stringify(fetchResponse, null, " ")}`
      );
    }

    return fetchResponse;
  }

  private async getPresentationDefinition(
    presentationUri: string,
    scope: string
  ): Promise<DIFPresentationDefinition> {
    try {
      const response = await fetch(`${presentationUri}?scope=${scope}`) as any;
      return await response.json();
    } catch (e: unknown) {
      throw new FetchError(`Can't recover presentation definition ${e}`);
    }
  }

}

class AuthenticationRequestWithCode {
  constructor(
    private signer: SignatureProvider,
    private code: string,
    private authMetadata: AuthServerMetadata
  ) { }

  async sendRequest(
    audience: string,
    externalAddr: string
  ): Promise<TokenResponse> {
    const pubKey = await this.signer.getPublicKey(PublicKeyFormat.JWK);
    const thumbprint = await calculateJwkThumbprint(pubKey);
    const currentTime = Math.floor(Date.now() / 1000) - 5; // Clock Tolerance
    const jwt = await this.signer.signJwt(
      {
        typ: "JWT",
        alg: await crvToAlg(pubKey.crv!),
        kid: thumbprint
      },
      {
        aud: audience,
        iss: externalAddr,
        iat: currentTime,
        nbf: currentTime,
        exp: currentTime + ((5 * 60))

      },
    );
    const body = querystring.stringify({
      grant_type: 'authorization_code',
      client_id: externalAddr,
      code: this.code,
      redirect_uri: externalAddr,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: jwt
    });
    try {
      const response = await fetch(this.authMetadata.token_endpoint!, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'accept-charset': 'utf-8',
        },
        body,
        redirect: 'manual'
      })
      const tokenResponse = await response.json() as any;
      if (tokenResponse.error) {
        throw new ExecutionFailed(
          `Authentication process failed with error: ${JSON.stringify(tokenResponse, null, "")}`
        )
      }
      return tokenResponse;
    } catch (e: unknown) {
      throw new FetchError(`Can't recover authn request: ${JSON.stringify(e, null, "")}`);
    }
  }
}

class AuthenticationRequestWithPreAuth {
  constructor(
    private preCode: string,
    private authMetadata: AuthServerMetadata
  ) { }

  async sendRequest(pinCode?: number): Promise<TokenResponse> {
    const body = querystring.stringify({
      grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      "pre-authorized_code": this.preCode,
      user_pin: pinCode,
    });
    try {
      const response = await fetch(this.authMetadata.token_endpoint!, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'accept-charset': 'utf-8',
        },
        body,
        redirect: 'manual'
      })
      const tokenResponse = await response.json() as any;
      if (tokenResponse.error) {
        throw new ExecutionFailed(
          `Authentication process failed with error: ${
            JSON.stringify(tokenResponse)
          }`
        )
      }
      return tokenResponse;
    } catch (e: unknown) {
      throw new FetchError(`Can't recover auth request: ${e}`);
    }
  }
}
