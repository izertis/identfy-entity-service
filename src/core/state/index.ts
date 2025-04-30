import {authBackend} from '../../shared/utils/functions/auth.utils.js';
import {BACKEND, NONCE_SERVICE} from '../../shared/config/configuration.js';
import {InternalServerError} from '../../shared/classes/error/httperrors.js';
import {NonceResponse} from '../../shared/interfaces/nonce.interface.js';
import fetch from 'node-fetch';
import * as jwt from 'jsonwebtoken';
import {JWTPayload} from 'jose';
import {StateManager} from 'openid-lib';

export class RemoteManager implements StateManager {
  async saveState(id: string, data: any): Promise<void> {
    let response;
    try {
      const currentTime = Math.floor(Date.now() / 1000);
      if (
        BACKEND.authorizationToken === undefined ||
        (((jwt.decode(BACKEND.authorizationToken)! as JWTPayload)
          .iat as number) < currentTime,
        {complete: false})
      ) {
        await authBackend(BACKEND.url);
      }
      response = await fetch(`${NONCE_SERVICE.url}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer ' + BACKEND.authorizationToken,
        },
        body: JSON.stringify({nonce: id, state: data}),
      });
    } catch (e: any) {
      throw new InternalServerError(
        "Can't send request to remote service",
        'server_error',
      );
    }
    if (!response.ok) {
      throw new InternalServerError(
        `Can't register state. Service responded with status ${response.status}`,
        'server_error',
      );
    }
  }

  async updateState(id: string, data: any): Promise<void> {
    let response;
    const currentTime = Math.floor(Date.now() / 1000);
    if (
      BACKEND.authorizationToken === undefined ||
      (((jwt.decode(BACKEND.authorizationToken)! as JWTPayload).iat as number) <
        currentTime,
      {complete: false})
    ) {
      await authBackend(BACKEND.url);
    }
    try {
      response = await fetch(`${NONCE_SERVICE.url}/${id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer ' + BACKEND.authorizationToken,
        },
        body: JSON.stringify({state: data}),
      });
    } catch (e: any) {
      throw new InternalServerError(
        "Can't send request to nonce service",
        'server_error',
      );
    }
    if (!response.ok) {
      throw new InternalServerError(
        `Can't update nonce. Service responded with status ${response.status}`,
        'server_error',
      );
    }
  }

  async getState(id: string): Promise<any | undefined> {
    let response;
    const currentTime = Math.floor(Date.now() / 1000);
    if (
      BACKEND.authorizationToken === undefined ||
      (((jwt.decode(BACKEND.authorizationToken)! as JWTPayload).iat as number) <
        currentTime,
      {complete: false})
    ) {
      await authBackend(BACKEND.url);
    }
    try {
      response = await fetch(`${NONCE_SERVICE.url}/${id}`, {
        method: 'GET',
        headers: {
          Authorization: 'Bearer ' + BACKEND.authorizationToken,
        },
      });
    } catch (e: any) {
      throw new InternalServerError(
        "Can't recover state information",
        'server_error',
      );
    }
    if (response.status === 404) {
      return undefined;
    }
    if (!response.ok) {
      throw new InternalServerError(
        `Can't get state. Service responded with status ${response.status}`,
        'server_error',
      );
    }
    return ((await response.json()) as NonceResponse).state;
  }

  async deleteState(id: string): Promise<void> {
    const currentTime = Math.floor(Date.now() / 1000);
    if (
      BACKEND.authorizationToken === undefined ||
      (((jwt.decode(BACKEND.authorizationToken)! as JWTPayload).iat as number) <
        currentTime,
      {complete: false})
    ) {
      await authBackend(BACKEND.url);
    }
    let response;
    try {
      response = await fetch(`${NONCE_SERVICE.url}/${id}`, {
        method: 'DELETE',
        headers: {
          Authorization: 'Bearer ' + BACKEND.authorizationToken,
        },
      });
    } catch (e: any) {
      throw new InternalServerError(
        "Can't send request to remote service",
        'server_error',
      );
    }
    if (!response.ok) {
      throw new InternalServerError(
        `Can't delete state. Service responded with status ${response.status}`,
        'server_error',
      );
    }
  }
}
