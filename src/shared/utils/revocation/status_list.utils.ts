import {
  StatusListCredentialData,
} from "../../../shared/interfaces/credential_status.interface";

export function generateStatusListVcData(
  listId: string,
  statusPurpose: "revocation" | "suspension",
  encodedList: string
): StatusListCredentialData {
  return {
    id: listId,
    type: "StatusList2021",
    statusPurpose,
    encodedList
  }
}
