import {DIFPresentationDefinition} from 'openid-lib';
import {STATUS_LIST_2021} from '../constants/credential_status.constants.js';

export enum RevocationTypes {
  NoRevocation = 'NoRevocation',
  StatusList2021 = STATUS_LIST_2021,
  EbsiAccreditationEntry = 'EbsiAccreditationEntry',
}

export interface VcScopeAction {
  scope: string;
  credential_types: string;
  response_type: 'vp_token' | 'id_token';
  credential_schema_address: string;
  presentation_definition?: DIFPresentationDefinition;
  is_deferred: boolean;
  revocation?: RevocationTypes;
  expires_in?: number;
  terms_of_use?: string;
  [K: string]: any;
}

export interface VpScopeAction {
  scope: string;
  response_type: 'vp_token' | 'id_token';
  presentation_definition: DIFPresentationDefinition;
}
