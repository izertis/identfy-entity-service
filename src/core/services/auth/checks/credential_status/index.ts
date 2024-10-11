import {
  VerificationResult,
  W3CCredentialStatus,
  W3CVerifiableCredential,
  decodeToken
} from "openid-lib";
import fetch from 'node-fetch';
import {
  STATUS_LIST_2021, STATUS_LIST_2021_VC
} from "../../../../../shared/constants/credential_status.constants.js";
import {
  StatusListEntry2021
} from "../../../../../shared/interfaces/credential_status.interface.js";
import { descompressGZIP } from "../../../../../shared/utils/gzip.utils.js";
import {
  getBitFromBitString
} from "../../../../../shared/utils/bitstring.utils.js";

export async function checkCredentialStatus(
  vc: W3CVerifiableCredential
): Promise<VerificationResult> {
  if (vc.credentialStatus) {
    if (Array.isArray(vc.credentialStatus)) {
      for (const status of vc.credentialStatus) {
        const result = await checkSingleCredentialStatus(status, vc.issuer);
        if (!result.valid) {
          return result;
        }
      }
    } else {
      return await checkSingleCredentialStatus(vc.credentialStatus, vc.issuer);
    }
  }
  return { valid: true };
}

async function checkSingleCredentialStatus(
  status: W3CCredentialStatus,
  issuer: string
): Promise<VerificationResult> {
  if (status.type !== STATUS_LIST_2021) {
    return { valid: false, error: "Unsupported credential status type" };
  }
  return await checkStatusList(status as StatusListEntry2021, issuer)
}

async function checkStatusList(
  credentialStatus: StatusListEntry2021,
  issuer: string
): Promise<VerificationResult> {
  if (
    credentialStatus.statusPurpose === "revocation" ||
    credentialStatus.statusPurpose === "suspension"
  ) {
    if (!credentialStatus.statusListCredential) {
      return {
        valid: false,
        error: "StatusList2021Entry must contain a statusListCredential parameter"
      }
    }
    const fetchResponse = await fetch(credentialStatus.statusListCredential);
    const statusVc = (await fetchResponse.text()).replace(/"/g, "");

    const jwt = decodeToken(statusVc);
    if (typeof jwt.payload === "string") {
      return {
        valid: false,
        error: "JWT Payload cannot be a String"
      }
    }
    if (jwt.payload.vc.issuer !== issuer) {
      return {
        valid: false,
        error: "StatusVC's issuer is not the same of the original VC"
      }
    }
    if (!jwt.payload.vc.validFrom) {
      return { valid: false, error: "StatusVC does not have a validFrom parameter" };
    }
    const validFrom = Math.floor(Date.parse(jwt.payload.vc.validFrom) / 1000);
    const now = Math.floor(Date.now() / 1000);
    const clockTolerance = 5;
    if (validFrom > (now + clockTolerance)) {
      return { valid: false, error: `StatusVc not yet valid: ${validFrom} > ${now}` };
    }
    const expDate = Math.floor(Date.parse(jwt.payload.vc.expirationDate) / 1000);
    if (expDate <= now) {
      return { valid: false, error: "StatusVC is expired" };
    }
    if (!(jwt.payload.vc.type as string[]).includes(STATUS_LIST_2021_VC)) {
      return { valid: false, error: `StatusVc is not of type ${STATUS_LIST_2021_VC}` };
    }
    if (jwt.payload.vc.credentialSubject.statusPurpose !== credentialStatus.statusPurpose) {
      return { valid: false, error: "StatusVC invalud status purpose" };
    }
    const listBase64Uncoded = Buffer.from(
      jwt.payload.vc.credentialSubject.encodedList,
      "base64"
    );
    const gzipUncodedList = await descompressGZIP(listBase64Uncoded);
    const indexValue = getBitFromBitString(gzipUncodedList, parseInt(credentialStatus.statusListIndex));
    if (indexValue === 1) {
      return { valid: false, error: "is revoked" };
    }
  } else {
    return { valid: false }
  }
  return { valid: true }
}