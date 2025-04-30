import { v4 as uuidv4 } from 'uuid';
import { JWK, JWTPayload } from "jose";
import jsonpath from "jsonpath";
import { Schema, Validator } from "jsonschema";
import fetch from "node-fetch";
import {
  DIFPresentationDefinition,
  DIFPresentationSubmission,
  IssuerMetadata,
  VpTokenRequestParams
} from 'openid-lib';
import {
  ExecutionFailed,
  FetchError
} from 'src/shared/classes/error/internalerror.js';
import { ES256_CODE } from 'src/shared/constants/jwa.constants.js';
import { decodeToken } from 'src/shared/utils/jwt.utils.js';

export async function recoverPresentationDefinition(
  payload: VpTokenRequestParams,
): Promise<DIFPresentationDefinition> {
  if (payload.presentation_definition) {
    return payload.presentation_definition;
  }
  if (!payload.presentation_definition_uri) {
    throw new ExecutionFailed(
      "It's not possible to recover presentation definition. Neither presentation_definition" +
      " or presentation_definition_uri parameter are present"
    );
  }
  try {
    const response = await fetch(
      `${payload.presentation_definition_uri}?scope=${payload.scope}`
    ) as any;
    return await response.json();
  } catch (e: any) {
    throw new FetchError(`Can't recover presentation definition ${e}`);
  }
}

export function verifyPresentationDefinition(
  presentationDefinition: DIFPresentationDefinition
) {
  if (presentationDefinition.format?.jwt_vc) {
    if (!presentationDefinition.format.jwt_vc.alg.includes(ES256_CODE as any)) {
      throw new ExecutionFailed(
        'Presentation definition does not support ES256 algorithm for VCs'
      );
    }
  }
  if (presentationDefinition.format?.jwt_vp) {
    if (!presentationDefinition.format.jwt_vp?.alg.includes(ES256_CODE as any)) {
      throw new ExecutionFailed(
        'Presentation definition does not support ES256 algorithm for VPs'
      );
    }
  }
}

export function selectCredentials(
  presentationDefinition: DIFPresentationDefinition,
  credentials: string[]
): [DIFPresentationSubmission, string[]] {
  const decodedCredentials = [];
  for (const credential of credentials) {
    decodedCredentials.push(decodeToken(credential).payload as JWTPayload)
  }
  const presentationSubmission: DIFPresentationSubmission = {
    id: uuidv4(),
    definition_id: presentationDefinition.id,
    descriptor_map: []
  }
  const credentialsSelected = [];
  for (const descriptor of presentationDefinition.input_descriptors) {
    let credentialSelected = '';
    for (const [index, credential] of decodedCredentials.entries()) {
      if (!descriptor.constraints.fields) {
        presentationSubmission.descriptor_map.push({
          id: descriptor.id,
          format: 'jwt_vp',
          path: '$',
          path_nested: {
            id: descriptor.id,
            format: 'jwt_vc',
            path: `$.vp.verifiableCredential[${credentialsSelected.length}]`
          }
        })
        credentialSelected = credentials[index];
        break;
      }
      let fieldsValidated = true;
      for (const field of descriptor.constraints.fields!) {
        const traversalObject = credential;
        let fieldSatisfy = false;
        for (const path of field.path) {
          const temporalTraversalObject = jsonpath.query(traversalObject, path);
          if (temporalTraversalObject) {
            for (const match of temporalTraversalObject) {
              const validator = new Validator();
              const validationResult = validator.validate(
                match,
                field.filter as Schema
              );
              if (!validationResult.errors.length) {
                fieldSatisfy = true;
                break;
              }
            }
            if (fieldSatisfy) {
              break;
            }
          }
        }
        if (!fieldSatisfy) {
          fieldsValidated = false;
          break;
        }
      }
      if (fieldsValidated) {
        credentialSelected = credentials[index];
        break;
      }
    }
    if (!credentialSelected) {
      throw new ExecutionFailed(
        'There aren\'t any credentials that satisfy the descriptor of the presentation'
      );
    }
    presentationSubmission.descriptor_map.push({
      id: descriptor.id,
      format: 'jwt_vp',
      path: '$',
      path_nested: {
        id: descriptor.id,
        format: 'jwt_vc',
        path: `$.vp.verifiableCredential[${credentialsSelected.length}]`
      }
    })
    credentialsSelected.push(credentialSelected);
  }
  return [
    presentationSubmission,
    credentialsSelected
  ]
}

export async function getIssuerMetadata(
  issuerUrl: string,
  discoveryPath: string
): Promise<IssuerMetadata> {
  const url = `${issuerUrl}/${discoveryPath}`;
  let issuerMetadata;
  try {
    issuerMetadata = await fetch(url, { method: "GET" });
  } catch (e: any) {
    throw new FetchError("Can't recover credential issuer metadata", e.message);
  }
  const jsonMetadata = await issuerMetadata.json() as any;
  return {
    credential_issuer: jsonMetadata['credential_issuer'],
    credential_endpoint: jsonMetadata['credential_endpoint'],
    authorization_server: jsonMetadata['authorization_server'],
    credentials_supported: jsonMetadata['credentials_supported'],
    deferred_credential_endpoint: jsonMetadata['deferred_credential_endpoint'],
  }
}

export async function getCredentialIssuerJWKs(url: string): Promise<JWK[]> {
  try {
    const response = await fetch(url);
    const jwks = await response.json() as any;
    return jwks['keys'];
  } catch (e: any) {
    throw new FetchError(`Can't recover credential issuer JWKs: ${e}`);
  }
}
