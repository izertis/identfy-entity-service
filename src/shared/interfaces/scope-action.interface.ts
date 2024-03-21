export interface VcScopeAction {
  scope: string;
  credential_types: string;
  response_type: "vp_token" | "id_token";
  credential_schema_address: string;
  presentation_definition?: string; // TODO: Change in the future
  is_deferred: boolean,
  [K: string]: any
}
