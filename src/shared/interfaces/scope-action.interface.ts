import { DIFPresentationDefinition } from "openid-lib";

export enum RevocationTypes {
  StatusList2021 = "StatusList2021",
}

export interface VcScopeAction {
  scope: string;
  credential_types: string;
  response_type: "vp_token" | "id_token";
  credential_schema_address: string;
  presentation_definition?: DIFPresentationDefinition;
  is_deferred: boolean;
  revocation?: RevocationTypes;
  expires_in?: number;
  [K: string]: any
}

export interface VpScopeAction {
  scope: string;
  response_type: "vp_token" | "id_token";
  presentation_definition: DIFPresentationDefinition
}
