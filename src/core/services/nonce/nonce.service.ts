import { autoInjectable, singleton } from "tsyringe";
import fetch from 'node-fetch';
import {
  NonceAccessTokenState,
  NonceAuthState,
  NoncePostState,
  NonceResponse,
  ResponseTypeOpcode
} from "../../../shared/interfaces/nonce.interface.js";
import { HttpError, InternalServerError } from "../../../shared/classes/errors.js";
import { NONCE_SERVICE } from "../../../shared/config/configuration.js";
import {
  AuthzErrorCodes,
  BearerTokenErrorCodes
} from "../../../shared/constants/error_codes.constants.js";

const AUTH_IDENTIFIER = "auth";
const POST_IDENTIFIER = "direct_post";
const ACCESS_TOKEN_IDENTIFIER = "access_token";

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
      type?: string
    }
  ) {
    let data;
    if (opcode === ResponseTypeOpcode.ISSUANCE) {
      if (!opts || !opts.codeChallenge || !opts.type) {
        throw new InternalServerError(
          "A problem has ocurred registering nonce",
          "server_error"
        );
      } else {
        data = [AUTH_IDENTIFIER, opcode, scope, redirect_uri, opts.codeChallenge, opts.type];
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
    codeChallenge?: string
  ) {
    const data = [POST_IDENTIFIER, scope];
    if (codeChallenge) {
      data.push(codeChallenge);
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
    try {
      response = await fetch(`${NONCE_SERVICE.url}/${nonce}`, {
        method: 'PATCH',
        headers: {
          "Content-Type": "application/json"
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
      response = await fetch(`${NONCE_SERVICE.url}`, {
        method: 'POST',
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ nonce, state, did: userId })
      });
    } catch (e: any) {
      // TODO: Define error type
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
    let response;
    try {
      response = await fetch(`${NONCE_SERVICE.url}/${nonce}`, {
        method: 'DELETE',
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
    try {
      response = await fetch(`${NONCE_SERVICE.url}/${nonce}`);
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
      if (!state[4] || !state[5]) {
        throw new InternalServerError(
          `Invalid auth state for nonce received`,
          AuthzErrorCodes.SERVER_ERROR
        );
      }
      return {
        opcode: state[1] as ResponseTypeOpcode,
        scope: state[2],
        redirect_uri: state[3],
        code_challenge: state[4],
        type: state[5],
        clientState: state[6]
      }
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
    if (state.length != 3 || state[0] != POST_IDENTIFIER) {
      // TODO: Define error type
      throw new InternalServerError(
        `The authz code has already been used or hasn't been generated yet`,
        AuthzErrorCodes.SERVER_ERROR
      );
    }
    return {
      scope: state[1],
      codeChallenge: state[2]
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
      // TODO: Define error type
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
