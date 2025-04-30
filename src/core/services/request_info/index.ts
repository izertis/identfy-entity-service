import {join as joinPath} from 'node:path/posix';
import {authBackend} from '../../../shared/utils/functions/auth.utils.js';
import {
  VcScopeAction,
  VpScopeAction,
} from '../../../shared/interfaces/scope-action.interface.js';
import {
  VERIFIABLE_ATTESTATION_TYPE,
  VERIFIABLE_CREDENTIAL_TYPE,
} from '../../../shared/constants/credential.constants.js';
import {
  VERIFIABLE_ACCREDITATION_TYPE
} from '../../../shared/constants/ebsi.constants.js';
import {BadRequestError} from '../../../shared/classes/error/httperrors.js';
import {
  AuthzErrorCodes
} from '../../../shared/constants/error_codes.constants.js';
import {BACKEND} from '../../../shared/config/configuration.js';
import fetch from 'node-fetch';
import {JWTPayload} from 'jose';
import * as jwt from 'jsonwebtoken';

/**
 * Allows to recover ScopeAction information for the issuance process
 * @param issuerUri The URI of the issuer
 * @param types The specific type of a credential
 * @returns The information associated with a specific issuance process
 */
export async function getIssuanceInfo(
  issuerUri: string,
  types: string | string[],
): Promise<VcScopeAction> {
  const entityUri = new URL(issuerUri);
  const urlAuth = `${entityUri.protocol}//${entityUri.host}`;
  const currentTime = Math.floor(Date.now() / 1000);
  if (
    BACKEND.authorizationToken === undefined ||
    (((jwt.decode(BACKEND.authorizationToken)! as JWTPayload).iat as number) <
      currentTime,
    {complete: false})
  ) {
    await authBackend(urlAuth.toString());
  }
  const uniqueType = Array.isArray(types)
    ? types.find(type => {
        return (
          type !== VERIFIABLE_CREDENTIAL_TYPE &&
          type !== VERIFIABLE_ATTESTATION_TYPE &&
          type !== VERIFIABLE_ACCREDITATION_TYPE
        );
      })
    : types;
  if (!uniqueType) {
    throw new BadRequestError(
      'Invalid VC type specified',
      AuthzErrorCodes.INVALID_REQUEST,
    );
  }
  const tmp = issuerUri.split('/');
  const issuerId = tmp[tmp.length - 1];
  const params = new URLSearchParams(
    Object.entries({
      credential_types: uniqueType,
      issuer: issuerId,
    }),
  ).toString();
  const url = new URL(BACKEND.url);
  url.pathname = joinPath(BACKEND.issuance_flow_path);
  const data = await fetch(`${url.toString()}?${params}`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer ' + BACKEND.authorizationToken,
    },
  });
  return (await data.json()) as VcScopeAction;
}

/**
 * Allows to recover ScopeAction information for the verification process
 * @param verifierUri The URI of the verifier
 * @param scope The scope of the verification process
 * @returns The information associated with a specific verification process
 */
export async function getVerificationInfo(
  verifierUri: string,
  scope: string,
): Promise<VpScopeAction> {
  const entityUri = new URL(verifierUri);
  const url = new URL(`${entityUri.protocol}//${entityUri.host}`);
  const currentTime = Math.floor(Date.now() / 1000);
  if (
    BACKEND.authorizationToken === undefined ||
    (((jwt.decode(BACKEND.authorizationToken)! as JWTPayload).iat as number) <
      currentTime,
    {complete: false})
  ) {
    await authBackend(url.toString());
  }
  const tmp = verifierUri.split('/');
  const issuerId = tmp[tmp.length - 1];
  const params = new URLSearchParams(
    Object.entries({
      scope,
      verifier: issuerId,
    }),
  ).toString();

  url.pathname = joinPath(BACKEND.verification_flow_path);
  const data = await fetch(`${url.toString()}?${params}`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer ' + BACKEND.authorizationToken,
    },
  });
  return (await data.json()) as VpScopeAction;
}
