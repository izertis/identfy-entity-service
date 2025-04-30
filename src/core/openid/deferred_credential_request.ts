import fetch from "node-fetch";
import { CredentialResponse } from "openid-lib";
import {
  ExecutionFailed,
  FetchError
} from "../../shared/classes/error/internalerror.js";

export class DeferredCredentialRequest {
  async sendRequest(
    credentialEndpoint: string,
    acceptanceToken: string
  ) {
    let response;
    try {
      response = await fetch(credentialEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Bearer ${acceptanceToken}`,
        },
      })
    } catch (e: unknown) {
      throw new FetchError(`Can't send deferred credential request: ${e}`);
    }
    if (!response.ok) {
      throw new ExecutionFailed(
        `Error received during deferred credential request execution: ${
          JSON.stringify(await response.json(), null, 1)
        }`
      )
    }
    const credentialResponse = await response.json() as any;
    return credentialResponse as CredentialResponse;
  }
}
