import {AuthServerMetadata } from "openid-lib";
import {
  FetchError,
  InvalidSigningAlg
} from "src/shared/classes/error/internalerror.js";
import {
  ES256_CODE,
  SUPPORTED_SIGNING_ALGORITHMS
} from "src/shared/constants/jwa.constants.js";

export async function getAndCheckAuthMetadata(
  serverUrl: string,
  discoveryPath: string
): Promise<AuthServerMetadata> {
  function getSigningAlg(algs: string[]): string {
    let supported = '';
    for (const alg of algs) {
      if (alg === 'none') {
        supported = ES256_CODE;
        break
      }
      if (SUPPORTED_SIGNING_ALGORITHMS.includes(alg as any)) {
        supported = alg;
        break;
      }
    }
    return supported;
  }
  const url = `${serverUrl}/${discoveryPath}`;
  let authMetadata;
  try {
    authMetadata = await fetch(url);
  } catch (e: any) {
    throw new FetchError("Can't recover auth metadata", e.message);
  }
  const jsonMetadata: any = await authMetadata.json();
  const pickedAlgIdToken = jsonMetadata['id_token_signing_alg_values_supported'] ?
    getSigningAlg(jsonMetadata['id_token_signing_alg_values_supported'])
    : ES256_CODE;
  const pickedAlgRequest = jsonMetadata['request_object_signing_alg_values_supported'] ?
    getSigningAlg(jsonMetadata['request_object_signing_alg_values_supported'])
    : ES256_CODE;
  if (!pickedAlgRequest) {
    throw new InvalidSigningAlg(
      'Unssuported signing algorithm detected for "request_object_signing_alg_values_supported"'
    );
  }
  return {
    ...jsonMetadata,
    id_token_signing_alg_values_supported: pickedAlgIdToken,
    request_object_signing_alg_values_supported: pickedAlgRequest
  };
}
