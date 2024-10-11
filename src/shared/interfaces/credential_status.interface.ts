export interface StatusListEntry2021 {
  id: string;
  type: "StatusList2021Entry";
  statusPurpose: "revocation" | "suspension";
  statusListIndex: string;
  statusListCredential: string;
}

export interface StatusListCredentialData {
  id: string;
  type: "StatusList2021",
  statusPurpose: "revocation" | "suspension";
  encodedList: string
}
