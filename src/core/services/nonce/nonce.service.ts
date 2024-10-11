import { autoInjectable, singleton } from "tsyringe";
import fetch from 'node-fetch';
import {
  NonceAccessTokenState,
  NonceAuthState,
  NoncePostState,
  NonceResponse,
  ResponseTypeOpcode
} from "../../../shared/interfaces/nonce.interface.js";
import {
  HttpError,
  InternalServerError
} from "../../../shared/classes/errors.js";
import { NONCE_SERVICE } from "../../../shared/config/configuration.js";
import {
  AuthzErrorCodes,
  BearerTokenErrorCodes
} from "../../../shared/constants/error_codes.constants.js";
import { JWK } from "jose";
import { authBackend } from "../../../shared/utils/functions/auth.utils.js";

const AUTH_IDENTIFIER = "auth";
const POST_IDENTIFIER = "direct_post";
const ACCESS_TOKEN_IDENTIFIER = "access_token";

enum WalletType {
  Service = "S",
  Holder = "H"
}

@singleton()
@autoInjectable()
export default class NonceService {
  constructor() { }

  /**
   * Registers a nonce with a status indicating the phase
   * in which it was generated was the approval phase.
   * @param userId The ID of the issuer
   * @param nonce The nonce to register
   * @param opcode The opcode of the state linking it to an
   * issuance or verification process
   * @param redirect_uri The URI to which the reply to the request
   * for authorisation should be submitted
   * @param scope The scope of the operation
   * @param opts Optional parameters that allows to define values for the
   * "code_challenge", "state" and "type" parameters
   */
  async registerNonceForAuth(
    userId: string,
    nonce: string,
    opcode: ResponseTypeOpcode,
    redirect_uri: string,
    scope: string,
    opts?: {
      codeChallenge?: string,
      clientState?: string,
      type?: string,
      serviceWalletJwk?: JWK
    }
  ) {
    let data;
    if (opcode === ResponseTypeOpcode.ISSUANCE) {
      if (!opts) {
        throw new InternalServerError(
          "Insufficiente number of arguments provided in nonce registration process",
          "server_error"
        );
      }
      if (opts.codeChallenge && opts.type) {
        data = [
          AUTH_IDENTIFIER,
          opcode,
          scope,
          WalletType.Holder,
          redirect_uri,
          opts.codeChallenge,
          opts.type
        ]
      } else if (opts.serviceWalletJwk && opts.type) {
        data = [
          AUTH_IDENTIFIER,
          opcode,
          scope,
          WalletType.Service,
          redirect_uri,
          JSON.stringify(opts.serviceWalletJwk),
          opts.type
        ]
      } else {
        throw new InternalServerError(
          "A problem has ocurred registering nonce",
          "server_error"
        );
      }
    } else {
      data = [AUTH_IDENTIFIER, opcode, scope, redirect_uri];
    }
    if (opts && opts.clientState) {
      data.push(opts.clientState);
    }
    await this.registerNonce(userId, nonce, data);
  }

  /**
   * Allows the status associated with a nonce to be updated to
   * one that reflects that it has passed the "direct_post" phase
   * @param nonce The nonce to update
   * @param scope The scope to include in the state
   * @param codeChallenge The codeChallenge to include in the state
   */
  async updateNonceForPostState(
    nonce: string,
    scope: string,
    clientId: string,
    codeChallenge?: string,
    serviceJwk?: JWK
  ) {
    const data = [POST_IDENTIFIER, scope, clientId];
    if (codeChallenge) {
      data.push(WalletType.Holder);
      data.push(codeChallenge);
    } else if (serviceJwk) {
      data.push(WalletType.Service);
      data.push(JSON.stringify(serviceJwk))
    }
    await this.updateNonceState(nonce, data);
  }

  /**
   * Allows the registration of the nonce to be used by an access token.
   * @param userId The ID of client
   * @param nonce The nonce to register
   * @param cNonce The challenge nonce to include in the state
   */
  async registerAccessTokenNonce(
    userId: string,
    nonce: string,
    cNonce: string
  ) {
    await this.registerNonce(userId, nonce, [ACCESS_TOKEN_IDENTIFIER, cNonce]);
  }

  private async updateNonceState(
    nonce: string,
    state: string[],
  ): Promise<NonceResponse> {
    let response;
    const authorize = await authBackend();
    try {
      response = await fetch(`${NONCE_SERVICE.url}/${nonce}`, {
        method: 'PATCH',
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer " + authorize
        },
        body: JSON.stringify({ state })
      })
    } catch (e: any) {
      throw new InternalServerError(
        "Can't send request to nonce service",
        "server_error"
      );
    }
    if (!response.ok) {
      throw new InternalServerError(
        `Can't update nonce. Service responded with status ${response.status}`,
        "server_error"
      );
    }
    return await response.json() as NonceResponse;
  }

  /**
   * Allows to update the state of nonce to that of an Access Token
   * @param nonce The nonce whose status will be updated
   * @param cNonce The challenge nonce to add to the state
   * @returns A NonceResponse with the nonce, did and state data
   */
  async updateChallengeNonce(
    nonce: string,
    cNonce: string,
  ): Promise<NonceResponse> {
    return await this.updateNonceState(nonce, [ACCESS_TOKEN_IDENTIFIER, cNonce]);
  }


  private async registerNonce(
    userId: string,
    nonce: string,
    state?: string[]
  ): Promise<NonceResponse> {
    let response;
    try {
      const authorize = await authBackend();
      response = await fetch(`${NONCE_SERVICE.url}`, {
        method: 'POST',
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer " + authorize
        },
        body: JSON.stringify({ nonce, state, did: userId })
      });
    } catch (e: any) {
      throw new InternalServerError(
        "Can't send request to nonce service",
        "server_error"
      );
    }
    if (!response.ok) {
      throw new InternalServerError(
        `Can't register nonce. Service responded with status ${response.status}`,
        "server_error"
      );
    }
    return await response.json() as NonceResponse;
  }

  /**
   * Allows to delete a nonce and its state
   * @param nonce The nonce to delete
   */
  async deleteNonce(nonce: string) {
    const authorize = await authBackend();
    let response;
    try {
      response = await fetch(`${NONCE_SERVICE.url}/${nonce}`, {
        method: 'DELETE',
        headers: {
          "Authorization": "Bearer " + authorize
        },
      });
    } catch (e: any) {
      throw new InternalServerError(
        "Can't send request to nonce service",
        "server_error"
      );
    }
    if (!response.ok) {
      throw new InternalServerError(
        `Can't delete nonce. Service responded with status ${response.status}`,
        "server_error"
      );
    }
  }

  /**
   * Allows to obtain a nonce and its associated state and client ID.
   * @param nonce The requested nonce
   * @returns The nonce with its client ID and state
   */
  async getNonce(nonce: string): Promise<NonceResponse | undefined> {
    let response;
    const authorize = await authBackend();
    try {
      response = await fetch(`${NONCE_SERVICE.url}/${nonce}`,
        {
          method: 'GET',
          headers: {
            "Authorization": "Bearer " + authorize
          },
        }
      );
    } catch (e: any) {
      throw new InternalServerError(
        "Can't recover nonce information",
        "server_error"
      );
    }
    if (response.status == 404) {
      return undefined;
    }
    if (!response.ok) {
      throw new InternalServerError(
        `Can't get nonce. Service responded with status ${response.status}`,
        "server_error"
      );
    }
    return await response.json() as NonceResponse;
  }

  /**
   * Checks if a state matches the expected status
   *  of a nonce generated after the initial authorisation phase.
   * @param state The state to check
   * @returns The deserialized state information
   */
  static verifyAuthNonceState(state: string[]): NonceAuthState {
    if (state.length < 4 || state[0] !== AUTH_IDENTIFIER) {
      throw new InternalServerError(
        `Invalid nonce specified`,
        AuthzErrorCodes.SERVER_ERROR
      );
    }
    const opcode = state[1] as ResponseTypeOpcode;
    if (opcode === ResponseTypeOpcode.ISSUANCE) {
      const walletType = state[3];
      if (!state[5] || !state[6]) {
        throw new InternalServerError(
          `Invalid auth state for nonce received`,
          AuthzErrorCodes.SERVER_ERROR
        );
      }
      const result = {
        opcode: state[1] as ResponseTypeOpcode,
        scope: state[2],
        redirect_uri: state[4],
        type: state[6],
        clientState: state[7]
      } as NonceAuthState;
      switch (walletType) {
        case WalletType.Holder:
          result.code_challenge = state[5];
          break;
        case WalletType.Service:
          result.serviceJwk = JSON.parse(state[5]);
          break;
      }
      return result;
    } else if (opcode === ResponseTypeOpcode.VERIFICATION) {
      return {
        opcode: state[1] as ResponseTypeOpcode,
        scope: state[2],
        redirect_uri: state[3],
        clientState: state[4]
      }
    } else {
      throw new InternalServerError(
        `Invalid auth nonce opcode received`,
        AuthzErrorCodes.SERVER_ERROR
      );
    }
  }

  /**
   * Checks if a state matches the expected state of a nonce
   *  generated after a successful call to the /direct_post endpoint.
   * @param state The state to check
   * @returns The deserialized state information
   */
  static verifyPostNonceState(state: string[]): NoncePostState {
    if (state.length != 5 || state[0] != POST_IDENTIFIER) {
      throw new InternalServerError(
        `The authz code has already been used or hasn't been generated yet`,
        AuthzErrorCodes.SERVER_ERROR
      );
    }
    switch (state[3]) {
      case WalletType.Holder:
        return {
          scope: state[1],
          clientDid: state[2],
          codeChallenge: state[4]
        }
      case WalletType.Service:
        return {
          scope: state[1],
          clientDid: state[2],
          serviceJwk: JSON.parse(state[4])
        }
      default:
        throw new InternalServerError(
          `Invalid associated state for PostNonce`,
          AuthzErrorCodes.SERVER_ERROR
        );
    }
  }

  /**
   * Checks if a state matches the expected state of a nonce
   *  generated after the issuance of a access token.
   * @param state The state to check
   * @returns The deserialized state information
   */
  static verifyAccessTokenNonceState(state: string[]): NonceAccessTokenState {
    if (state.length != 2 || state[0] != ACCESS_TOKEN_IDENTIFIER) {
      throw new HttpError(
        BearerTokenErrorCodes.INVALID_TOKEN.httpStatus,
        BearerTokenErrorCodes.INVALID_TOKEN.code,
        `The access token is not longer valid`,
      );
    }
    return {
      cNonce: state[1]
    }
  }
}
