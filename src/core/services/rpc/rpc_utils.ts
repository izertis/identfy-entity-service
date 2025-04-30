import {EBSI} from "../../../shared/config/configuration.js";
import {
  InternalServerError
} from "../../../shared/classes/error/httperrors.js";
import {
  SCOPE_TIR_ONBOARD,
  SCOPE_TIR_WRITE
} from "../../../shared/constants/ebsi.constants.js";
import fetch from "node-fetch";

interface IssuerEbsiResponse {
  did: string;
  attributes: {
    hash: string;
    body: string;
    issuerType: "TI" | "TAO" | "RTAO" | "REVOKED";
    tao: string;
    rootTao: string
  }[]
}

export async function getScopeToUseForTIR(issuerDid: string) {
  let response;
  try {
    response = await fetch(`${EBSI.tir_url}/issuers/${issuerDid}`);
  } catch (e: any) {
    throw new InternalServerError(e.message, "fetching_resource_error");
  }
  if (response.status === 404) {
    return SCOPE_TIR_ONBOARD;
  }
  const responseJson = await response.json() as IssuerEbsiResponse;
  for (const attribute of responseJson.attributes) {
    if (attribute.body.length > 0) {
      return SCOPE_TIR_WRITE;
    }
  }
  return SCOPE_TIR_ONBOARD;
}
