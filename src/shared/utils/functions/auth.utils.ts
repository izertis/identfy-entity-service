import {BACKEND} from '../../config/configuration.js';
import {join as joinPath} from 'node:path/posix';
import fetch from 'node-fetch';
import {JWK, JWTPayload} from 'jose';
import {HttpError} from '../../classes/error/httperrors.js';
import * as jwt from 'jsonwebtoken';
import { KeyFormat, KeysType } from '../../../shared/types/keys.type.js';

export interface AuthLogin {
  refresh: string;
  access: string;
  user_id: number;
  username: string;
  email: string;
}
export interface OrganizationKey {
  id: string;
  name: string;
  type: string;
  format: string;
  value: string;
  organization: string;
}
export interface SignatureInputInformation {
  format: KeyFormat;
  type: KeysType;
  value: JWK;
}

// TODO: Refactor and change to one call or recall when it is expired
export async function authBackend(url: string) {
  const urlBackend = new URL(url);
  urlBackend.pathname = joinPath('/api/api-token-auth');
  const body = {
    username: BACKEND.user as string,
    password: BACKEND.password as string,
  };
  const response = await fetch(urlBackend.toString(), {
    method: 'post',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  const data = (await response.json()) as AuthLogin;
  BACKEND.authorizationToken = data.access;
}

export async function keysBackend(
  issuerUri: string,
  type: string,
): Promise<SignatureInputInformation> {
  const entityUri = new URL(issuerUri);
  const url = `${entityUri.protocol}//${entityUri.host}`;
  entityUri.pathname = joinPath('/organization-keys/');
  entityUri.searchParams.append('type', type);
  const currentTime = Math.floor(Date.now() / 1000);
  if (
    BACKEND.authorizationToken === undefined ||
    (((jwt.decode(BACKEND.authorizationToken)! as JWTPayload).iat as number) <
      currentTime,
    {complete: false})
  ) {
    await authBackend(url);
  }
  const response = await fetch(entityUri.toString(), {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer ' + BACKEND.authorizationToken,
    },
  });
  if (response.status === 500) {
    throw new HttpError(
      response.status,
      'ERROR GETTING DATA',
      'Something went wrong retriving keys',
    );
  }

  const data = (await response.json()) as JSON[];
  const signatureInputInformation: SignatureInputInformation =
    await getSignatureInformation(data[0] as unknown as OrganizationKey);
  return signatureInputInformation;
}

export async function getSignatureInformation(
  keys: OrganizationKey,
): Promise<SignatureInputInformation> {
  const format = keys.format as KeyFormat;
  const type = keys.type as KeysType;
  let value;
  switch (format) {
    case KeyFormat.JWK:
      value = keys.value as unknown as JWK;
      break;
  }

  return {format, type, value} as SignatureInputInformation;
}

export async function crvToAlg(crv: string): Promise<string> {
  let alg = 'ES256';
  switch (crv) {
    case 'P-256':
      alg = 'ES256';
      break;
    case 'secp256k1':
      alg = 'ES256K';
      break;
  }

  return alg;
}
