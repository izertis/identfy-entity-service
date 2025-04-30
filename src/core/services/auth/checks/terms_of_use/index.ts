import * as jose from 'jose';
import fetch from 'node-fetch';
import {
  EBSI_CONFORMANCE_RTAO_DID,
  EBSI_SUPPORT_OFFICE_DID,
  EBSI_TERM_OF_USE_TYPE,
  EbsiAccreditationType,
} from '../../../../../shared/constants/ebsi.constants.js';
import {ChainCheckAccreditationType} from './accreditation_chain.js';
import {
  AsyncChainHandler,
  Context,
  HandlerWithContext,
} from '../../../../../shared/classes/utility/handler.js';
import {
  VerificationResult,
  W3CTermsOfUse,
  W3CVerifiableCredential,
} from 'openid-lib';

interface TirAttributeResponse {
  did: string;
  attribute: {
    hash: string;
    body: string;
    issuerType: IssuerType;
    tao: string;
    rootTao: string;
  };
}

enum IssuerType {
  TAO = 'TAO',
  TI = 'TI',
  RTAO = 'RootTAO',
  REVOKED = 'Revoked',
}

interface DerefenceData {
  issuerType: IssuerType;
  jwtVc: Record<string, any>;
}

export async function checkTrustChain(
  jwtVc: W3CVerifiableCredential,
): Promise<VerificationResult> {
  const resolve = async (term: W3CTermsOfUse): Promise<VerificationResult> => {
    if (term.type !== EBSI_TERM_OF_USE_TYPE) {
      return {valid: false, error: 'Invalid terms of use type'};
    }
    const certificateVc = await getFromUrl(term.id!);
    const deferenceData = tirDereference(certificateVc);
    const checkResult = new ChainCheckAccreditationType(jwtVc.type)
      .isAccreditation()
      .collect();
    const context = Context.fromObject({deferenceData, originalVc: jwtVc});
    let taoHandler,
      tiHandler = undefined;
    if (checkResult.isError()) {
      // The VC is not an accreditation
      taoHandler = generateTaoHandlerForAttestation();
      tiHandler = generateTiHandlerForAttestation();
    } else {
      // The VC is an accreditation
      taoHandler = generateTaoHandlerForAccreditation();
      tiHandler = generateTiHandlerForAccreditation();
    }
    return await resolveAccreditation(context, taoHandler, tiHandler);
  };
  if (!jwtVc.termsOfUse) {
    throw new Error('No terms of use parameter');
  }
  if (Array.isArray(jwtVc.termsOfUse)) {
    for (const term of jwtVc.termsOfUse) {
      const result = await resolve(term);
      if (!result.valid) {
        return result;
      }
    }
  } else {
    const result = await resolve(jwtVc.termsOfUse);
    if (!result.valid) {
      return result;
    }
  }
  return {valid: true};
}

function generateTaoHandlerForAttestation() {
  return new (class extends HandlerWithContext {
    async handle(context: Context): Promise<void> {
      const deferenceDataPointer =
        context.getMutOrThrow<DerefenceData>('deferenceData');
      const originalVc = context.getOrThrow<Record<string, any>>('originalVc');
      const accreditVc = deferenceDataPointer.value.jwtVc;
      analyzeAttestationVc(
        deferenceDataPointer.value.jwtVc,
        originalVc,
        'VerifiableAccreditationToAccredit',
      );
      const certificateVc = await getFromUrl(accreditVc.vc.termsOfUse.id);
      deferenceDataPointer.value = tirDereference(certificateVc);
    }
  })();
}

function generateTaoHandlerForAccreditation() {
  return new (class extends HandlerWithContext {
    async handle(context: Context): Promise<void> {
      const deferenceDataPointer =
        context.getMutOrThrow<DerefenceData>('deferenceData');
      const certificateVc = await getFromUrl(
        deferenceDataPointer.value.jwtVc.vc.termsOfUse.id,
      );
      deferenceDataPointer.value = tirDereference(certificateVc);
    }
  })();
}

function generateTiHandlerForAttestation() {
  return new (class extends HandlerWithContext {
    async handle(context: Context): Promise<void> {
      const deferenceDataPointer =
        context.getMutOrThrow<DerefenceData>('deferenceData');
      const originalVc = context.getOrThrow<Record<string, any>>('originalVc');
      const accreditVc = deferenceDataPointer.value.jwtVc;
      analyzeAttestationVc(
        deferenceDataPointer.value.jwtVc,
        originalVc,
        'VerifiableAccreditationToAttest',
      );
      const certificateVc = await getFromUrl(accreditVc.vc.termsOfUse.id);
      deferenceDataPointer.value = tirDereference(certificateVc);
    }
  })();
}

function generateTiHandlerForAccreditation() {
  return new (class extends HandlerWithContext {
    handle(_context: Context): Promise<void> {
      return new Promise((_resolve, reject) => {
        reject(
          new Error(
            'Invalid accreditation. Accreditation was issued by a TI, not a TAO or RTAO',
          ),
        );
      });
    }
  })();
}

async function getFromUrl(url: string): Promise<TirAttributeResponse> {
  const response = await fetch(url);
  return (await response.json()) as TirAttributeResponse;
}

function tirDereference(tirEntry: TirAttributeResponse): DerefenceData {
  if (!tirEntry.attribute.body.length) {
    throw new Error('Issuer has not a credential registered yet');
  }
  const jwt = jose.decodeJwt(tirEntry.attribute.body) as Record<string, any>;
  if (!jwt.vc.type.includes('VerifiableAttestation')) {
    throw new Error('VC must be a subtype of VerifiableAttestation');
  }
  if (tirEntry.did !== jwt.vc.credentialSubject.id) {
    throw new Error(
      'VC was issued for a different entity that the one specified in the registry',
    );
  }
  const check = new ChainCheckAccreditationType(jwt.vc.type)
    .isAccreditation()
    .unique();
  check.collect().consume();
  return {issuerType: tirEntry.attribute.issuerType, jwtVc: jwt};
}

function analyzeAttestationVc(
  accreditVc: Record<string, any>,
  originalVc: Record<string, any>,
  typeToCheck: EbsiAccreditationType,
): void {
  // TODO: Here we have a problem. For some reason, the EBSI Help Desk sometimes register an acreditation with a IssuerType
  // different that the one specified in the TIR entry. For example, they register a VerifiableAuthorisationForTrustChain as
  // TAO instead of RTAO. This made the following condition to fail when it shouldn't
  if (!accreditVc.vc.type.includes(typeToCheck)) {
    throw new Error(`The VC must contain one of these types ${typeToCheck}`);
  }
  let resultFound = false;
  for (const accreditedFor of accreditVc.vc.accreditedFor) {
    if (accreditedFor.schemaId === originalVc.vc.credentialSchema.id) {
      if (
        (originalVc.vc.type as Array<string>).every(x =>
          accreditedFor.types.includes(x),
        )
      ) {
        resultFound = true;
        break;
      }
    }
  }
  if (!resultFound) {
    throw new Error(
      'Invalid issuance certificate detected in trust chain. Issuer not allowed to issue VC',
    );
  }
  for (const type of originalVc.type) {
    if (!accreditVc.vc.credentialSubject.accreditedFor.includes(type)) {
      throw new Error(`Entity is not accredited for type ${type}`);
    }
  }
}

async function resolveAccreditation(
  context: Context,
  taoHandler: AsyncChainHandler,
  tiHandler: AsyncChainHandler,
): Promise<VerificationResult> {
  const deferenceData = context.getOrThrow<DerefenceData>('deferenceData');
  try {
    switch (deferenceData.issuerType) {
      case IssuerType.RTAO:
        if (
          deferenceData.jwtVc.vc.issuer !== EBSI_SUPPORT_OFFICE_DID &&
          deferenceData.jwtVc.vc.issuer !== EBSI_CONFORMANCE_RTAO_DID
        ) {
          return {
            valid: false,
            error:
              'RTAO accreditations can only be issued by the EBSI Support Office',
          };
        }
        // TODO: Here the CredentialSUbject ID could be checked against a white list of trusted entities for the use case
        return {valid: true};
      case IssuerType.TAO:
        await taoHandler.handle(context);
        return resolveAccreditation(context, taoHandler, tiHandler);
      case IssuerType.TI:
        await tiHandler.handle(context);
        return resolveAccreditation(context, taoHandler, tiHandler);
      case IssuerType.REVOKED:
        return {
          valid: false,
          error: 'The accreditation was revoked',
        };
      default:
        return {
          valid: false,
          error: `Unexpected IssuerType received: "${deferenceData.issuerType}"`,
        };
    }
  } catch (e: any) {
    // TODO: TO avoid this catch, maybe the handlers should return a Result type
    return {valid: true, error: (e as Error).message};
  }
}
