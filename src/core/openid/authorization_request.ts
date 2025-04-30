import querystring from "querystring";
import { calculateJwkThumbprint, JWK } from "jose";
import fetch from "node-fetch";
import {
  SignatureProvider
} from "../../shared/classes/signature_provider/index.js";
import {
  AuthServerMetadata,
  IdTokenRequestParams,
  VpTokenRequestParams} from "openid-lib";
import {AUTHZ_RESPONSE_TYPE} from "../../shared/constants/openid.constants.js";
import {PublicKeyFormat} from "../../shared/types/keys.type.js";
import {crvToAlg} from "../../shared/utils/functions/auth.utils.js";
import {
  ExecutionFailed,
  FetchError,
  OpenIDError
} from "../../shared/classes/error/internalerror.js";
import {manageRedirection} from "../../shared/utils/url.utils.js";
import {verifyJWS} from "../../shared/utils/jws.utils.js";
import {ExtendedAuthzRequest} from "../../shared/interfaces/auth.interface.js";

export class AuthorizationRequest {
  constructor(
    protected signer: SignatureProvider,
    protected authMetadata: AuthServerMetadata
  ) { }

  async sendRequest(
    scope: string,
    externalAddr: string,
    additionalPayload: Record<string, any>,
    audience: string,
    jwks: JWK[]
  ): Promise<VpTokenRequestParams | IdTokenRequestParams> {
    const AuthServerMetadata = await this.sendData(
      scope,
      externalAddr,
      additionalPayload,
      audience
    );
    const requestJwt = await this.recoverRequest(AuthServerMetadata);
    const jwt = await this.verifyJWS(requestJwt, jwks);
    return jwt.payload as any as VpTokenRequestParams | IdTokenRequestParams;
  }

  private async sendData(
    scope: string,
    externalAddr: string,
    additionalPayload: Record<string, any>,
    audience: string,
  ): Promise<ExtendedAuthzRequest> {
    const AUTH_ENDPOINT = 'openid:';
    const params = {
      client_id: externalAddr,
      response_type: AUTHZ_RESPONSE_TYPE,
      scope,
      redirect_uri: externalAddr,
    };
    const payload = {
      ...params,
      ...additionalPayload
    }
    const pubKey = await this.signer.getPublicKey(PublicKeyFormat.JWK);
    const thumbprint = await calculateJwkThumbprint(pubKey);
    const currentTime = Math.floor(Date.now() / 1000) - 5; // Clock Tolerance

    const jwt = (await this.signer.signJwt(
      {
        typ: "JWT",
        alg: await crvToAlg(pubKey.crv!),
        kid: thumbprint
      },
     {...payload,
      aud: audience,
      iss: externalAddr,
      iat: currentTime,
      nbf: currentTime,
      exp: currentTime + ((5 * 60))
     }

    ));
    const url = `${this.authMetadata.authorization_endpoint}?${querystring.stringify({
      ...params,
      request: jwt
    })}`;
    let authRequest: ExtendedAuthzRequest = {};
    try {
      await fetch(url, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'accept-charset': 'utf-8',
        },
        redirect: 'manual'
      })
        .then((response) => {
          authRequest = manageRedirection(response, `?`);
        })
    } catch (e: any) {
      throw new FetchError(`Can't recover auth request: ${e}`);
    }
    if (authRequest.error) {
      throw new ExecutionFailed(`Request Authorization failed with error: ${authRequest.error}`)
    }
    return authRequest;
  }

  private async verifyJWS(requestJwt: string, jwks: JWK[]) {
    return await verifyJWS(requestJwt, (kid: string) => {
      const result = jwks.find((value) => {
        return value.kid === kid;
      });
      if (!result) {
        throw new ExecutionFailed('"kid" not found in JWKs');
      }
      return result;
    });
  }

  private async recoverRequest(
    request: ExtendedAuthzRequest
  ) {
    if (request.request) {
      return request.request;
    } else if (request.request_uri) {
      try {
        const response = await fetch(request.request_uri);
        return await response.text();
      } catch (e: any) {
        throw new FetchError(`Can't recover auth request from 'request_uri' parameter: ${e}`);
      }
    } else {
      throw new OpenIDError(
        'No "request" or "request_uri" parameter found in the Auth Request received from EBSI'
      );
    }
  }
}
