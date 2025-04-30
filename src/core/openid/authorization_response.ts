import querystring from "querystring";
import { v4 as uuidv4 } from 'uuid';
import {
  recoverPresentationDefinition,
  selectCredentials,
  verifyPresentationDefinition
} from "./utils.js";
import fetch from "node-fetch";
import { IdTokenRequestParams, VpTokenRequestParams } from "openid-lib";
import { AuthResponse } from "../../shared/interfaces/auth.interface.js";
import {
  SUPPORTED_RESPONSE_MODE
} from "../../shared/constants/openid.constants.js";
import {
  ExecutionFailed,
  FetchError,
  OpenIDError
} from "../../shared/classes/error/internalerror.js";
import { getKidFromDID } from "../../shared/utils/kid.utils.js";
import { crvToAlg } from "../../shared/utils/functions/auth.utils.js";
import { manageRedirection } from "../../shared/utils/url.utils.js";
import {
  SignatureProvider
} from "../../shared/classes/signature_provider/index.js";
import { PublicKeyFormat } from "../../shared/types/keys.type.js";


export class IdTokenAuthorizationResponse {
  constructor(private signer: SignatureProvider) { }

  async sendIdToken(
    authRequest: IdTokenRequestParams,
    did: string,
    externalAddr: string,
    audience: string
  ): Promise<AuthResponse> {
    if (authRequest.response_mode !== SUPPORTED_RESPONSE_MODE) {
      throw new ExecutionFailed(
        `"response_mode" ${authRequest.response_mode} not supported`
      );
    }
    const pubKey = await this.signer.getPublicKey(PublicKeyFormat.JWK);
    const kid = await getKidFromDID(did, this.signer);
    const currentTime = Math.floor(Date.now() / 1000) - 5; // Clock Tolerance

    let idTokenResult;
    try {
      idTokenResult = await this.signer.signJwt(
        {
          typ: "JWT",
          alg: await crvToAlg(pubKey.crv!),
          kid: kid
        },
        {
          iss: did,
          aud: audience,
          state: authRequest.state,
          nonce: authRequest.nonce,
          iat: currentTime,
          nbf: currentTime,
          exp: currentTime + ((5 * 60)),
          sub: did
        },
      );
    } catch (e: any) {
      throw new ExecutionFailed(
        `ID Token generation failed: ${e}`
      );
    }
    const body = querystring.stringify({
      state: authRequest.state,
      id_token: idTokenResult,
    });
    let code: string | null;
    try {
      await fetch(authRequest.redirect_uri, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'accept-charset': 'utf-8',
        },
        body,
        redirect: 'manual'
      }).then(async (response) => {
        const data = manageRedirection(response, externalAddr);
        code = data.code;
        if (!code) {
          throw new OpenIDError(`No "code" parameter in AuthResponse`);
        }
      })
    } catch (e: unknown) {
      throw new FetchError(`Can't send ID Token response: ${e}`);
    }
    return {
      code: code!
    }
  }
}

export class VpTokenAuthorizationResponse {
  constructor(private signer: SignatureProvider) { }

  async sendVpToken(
    authRequest: VpTokenRequestParams,
    did: string,
    audience: string,
    credentials: string[],
    externalAddr: string,
  ): Promise<AuthResponse> {
    const presentationDefinition = await recoverPresentationDefinition(
      authRequest
    );
    verifyPresentationDefinition(presentationDefinition);
    const [submission, selectedCredentials] = selectCredentials(
      presentationDefinition,
      credentials
    );
    const pubKey = await this.signer.getPublicKey(PublicKeyFormat.JWK);
    const kid = await getKidFromDID(
      did,
      this.signer
    );
    const currentTime = Math.floor(Date.now() / 1000) - 5; // Clock Tolerance
    let vp_token;
    try {
      vp_token = await this.signer.signJwt(
        {
          typ: "JWT",
          alg: await crvToAlg(pubKey.crv!),
          kid: kid
        },
        { aud: audience,
          iss: did,
          nonce: uuidv4(),
          vp: {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            id: uuidv4(),
            type: ['VerifiablePresentation'],
            holder: did,
            verifiableCredential: selectedCredentials
          },
          iat: currentTime,
          nbf: currentTime,
          exp: currentTime + ((5 * 60)),
          sub: did
        },
      );
    } catch (e: any) {
      throw new ExecutionFailed(`An error happened during VP Token generation ${e}`);
    }

    const body = querystring.stringify({
      state: authRequest.state,
      vp_token: vp_token,
      presentation_submission: JSON.stringify(submission)
    });
    let code: string | null;
    try {
      await fetch(authRequest.redirect_uri, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'accept-charset': 'utf-8',
        },
        body,
        redirect: 'manual'
      }).then(async (response) => {
        const data = manageRedirection(response, externalAddr);
        code = data.code;
        if (!code) {
          throw new OpenIDError(`No "code" parameter in AuthResponse`);
        }
      });
    } catch (e: unknown) {
      throw new FetchError(`Can't send VP Token Response: ${e}`);
    }
    return {
      code: code!
    }
  }
}
