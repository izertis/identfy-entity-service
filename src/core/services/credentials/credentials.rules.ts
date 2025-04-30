import {autoInjectable, singleton} from 'tsyringe';
import {
  W3CVcIssuer,
  CredentialSupportedBuilder,
  BaseControlProof,
  ControlProof,
  VcSignCallback,
  W3CVcSchemaDefinition,
} from 'openid-lib';
import {Resolver} from 'did-resolver';
import {
  HttpError,
  InternalServerError,
} from '../../../shared/classes/error/httperrors.js';
import {
  CredentialErrorCodes
} from '../../../shared/constants/error_codes.constants.js';
import {getResolver as keyDidResolver} from '@cef-ebsi/key-did-resolver';
import {
  VERIFIABLE_ATTESTATION_TYPE,
  VERIFIABLE_CREDENTIAL_TYPE,
} from '../../../shared/constants/credential.constants.js';
import Logger from '../../../shared/classes/logger.js';
import {AccessTokenPayload} from '../../../shared/interfaces/auth.interface.js';
import {getResolver as ebsiDidResolver} from '@cef-ebsi/ebsi-did-resolver';
import {
  ACCREDITATIONS_TYPES,
  VERIFIABLE_ACCREDITATION_TYPE,
} from '../../../shared/constants/ebsi.constants.js';
import {RemoteManager} from '../../state/index.js';
import {EbsiDataManager} from './data_manager/ebsi_manager.js';
import {
  RevocationTypes
} from '../../../shared/interfaces/scope-action.interface.js';
import {StatusVcDataProvider} from './data_manager/status_manager.js';
import {
  crvToAlg,
  keysBackend,
} from '../../../shared/utils/functions/auth.utils.js';
import {CREDENTIAL, EBSI} from '../../../shared/config/configuration.js';
import {JWK} from 'jose';
import {
  SchemaGetterFactory
} from '../../../shared/classes/schemas/getschema.factory.js';
import {JwtPayload} from 'jsonwebtoken';
import {
  SchemaValidatorFactory
} from '../../../shared/classes/schemas/schemavalidator.factory.js';
import {
  SignatureProvider
} from '../../../shared/classes/signature_provider/index.js';
import {PublicKeyFormat} from '../../../shared/types/keys.type.js';
import {getKidFromDID} from '../../../shared/utils/kid.utils.js';

@singleton()
@autoInjectable()
export default class CredentialsRules {
  didResolver = new Resolver({
    ...keyDidResolver(),
    ...ebsiDidResolver({
      registry: EBSI.did_registry,
    }),
  });

  constructor(private logger: Logger) { }

  getKidResolver = async (
    signature: SignatureProvider,
    did: string,
    pubKey: JWK,
  ): Promise<string> => {
    return await getKidFromDID(
      did,
      signature
    );
  };

  async generateSignCallback(
    signatureProvider: SignatureProvider,
    publicJWK: JWK,
    kid: string,
  ): Promise<VcSignCallback> {
    return async (_format, vc) => {
      // For now, we only support JsonSchema and only one schema specification
      const credentialSchema = (vc as JwtPayload).vc
        .credentialSchema as W3CVcSchemaDefinition;
      if (!CREDENTIAL.skip_vc_verification.includes(credentialSchema.id)) {
        const schemaValidatorResult = await SchemaGetterFactory.generateGetter(
          credentialSchema.type,
        ).getSchema(credentialSchema.id);
        if (schemaValidatorResult.isError()) {
          throw new InternalServerError(
            'Error retrieving VC Schema',
            'server_error',
          );
        }
        const schema = schemaValidatorResult.unwrap();
        const schemaValidator = SchemaValidatorFactory.generateValidator(schema);
        if (!(await schemaValidator.validate(vc.vc))) {
          this.logger.error(
            'The data provided by the Authentic Source does not validate VC schema',
          );
          throw new InternalServerError('Error generating VC', 'server_error');
        }
      }
      const header = {
        alg: await crvToAlg(publicJWK.crv!),
        typ: 'JWT',
        kid: kid,
      };
      return (await signatureProvider.signJwt(header, vc));
    };
  }

  /**
   * Generate an instance of W3CVcIssuer that is able to generate
   * VC for both the deferred and In-TIme flows
   * @param issuerUri The URI of the issuer
   * @param vcTypes The VC types that will be supported
   * @param issuerDid The DID of the issuer
   * @param signatureProvider Object that allows the generations of signatures
   * @param vcSchema The schema identifier for the VC
   * @param isDeferred A flag that indicated if the VC should follow the deferred flow
   * @returns An instance of W3CVcIssuer
   */
  async buildVcIssuer(
    issuerUri: string,
    vcTypes: string | string[],
    issuerDid: string,
    signatureProvider: SignatureProvider,
    listId?: string,
    listIndex?: number,
    listProxy?: string,
    accessToken?: AccessTokenPayload,
  ): Promise<W3CVcIssuer> {
    this.logger.log(`Generating VcIssuer for ${issuerUri}`);
    if (!Array.isArray(vcTypes)) {
      if (
        ACCREDITATIONS_TYPES.includes(
          vcTypes as (typeof ACCREDITATIONS_TYPES)[number],
        )
      ) {
        vcTypes = [
          VERIFIABLE_ATTESTATION_TYPE,
          VERIFIABLE_CREDENTIAL_TYPE,
          VERIFIABLE_ACCREDITATION_TYPE,
          vcTypes,
        ];
      } else {
        vcTypes = [
          VERIFIABLE_ATTESTATION_TYPE,
          VERIFIABLE_CREDENTIAL_TYPE,
          vcTypes,
        ];
      }
    }
    const publicJWK = await signatureProvider.getPublicKey(PublicKeyFormat.JWK);
    const kid = await this.getKidResolver(signatureProvider, issuerDid, publicJWK);
    const credentialSupported = [
      new CredentialSupportedBuilder()
        .withFormat('jwt_vc')
        .withTypes(vcTypes)
        .build(),
    ];
    return new W3CVcIssuer(
      // Metadata
      {
        credential_issuer: issuerUri,
        credential_endpoint: issuerUri + '/credentials/',
        credentials_supported: credentialSupported,
      },
      this.didResolver,
      issuerDid,
      // Sign Callback
      // TODO: There are two different points in the code that generates a signature
      // We need to combine both of them into a single one
      await this.generateSignCallback(signatureProvider, publicJWK, kid),
      // State Manager
      new RemoteManager(),
      await EbsiDataManager.buildManager(
        issuerUri,
        issuerDid,
        signatureProvider,
        listId
          ? {
            type: RevocationTypes.StatusList2021,
            listId: listId!,
            listIndex: listIndex!,
            listProxy: listProxy!,
          }
          : {
            type: RevocationTypes.NoRevocation,
          },
        kid,
        this.logger,
        accessToken,
      )
    );
  }

  async buildVcIssuerForStatusVc(
    issuerUri: string,
    issuerDid: string,
    statusPurpose: 'revocation' | 'suspension',
    listId: string,
    statusList: string,
    _revocationType: 'StatusList2021',
  ) {
    // For now we only support StatusList2021. When we support more than one
    // strategy, we will have to change this function as well.
    const vcTypes = StatusVcDataProvider.getAssociatedTypes();
    const contexts = StatusVcDataProvider.getLinkedContext();
    const keys_256r1 = await keysBackend(issuerUri, 'secp256r1');
    const signatureProvider256r1 = (
      await SignatureProvider.generateProvider(
        keys_256r1.format,
        keys_256r1.type,
        keys_256r1.value,
      )
    );
    const pubKey = await signatureProvider256r1.getPublicKey(
      PublicKeyFormat.JWK,
    );
    const kid = await this.getKidResolver(
      signatureProvider256r1,
      issuerDid,
      pubKey,
    );
    const credentialSupported = [
      new CredentialSupportedBuilder()
        .withFormat('jwt_vc')
        .withTypes(vcTypes)
        .build(),
    ];
    return new W3CVcIssuer(
      // Metadata
      {
        credential_issuer: issuerUri,
        credential_endpoint: issuerUri + '/credentials/',
        credentials_supported: credentialSupported,
      },
      this.didResolver,
      issuerDid,
      // Sign Callback
      await this.generateSignCallback(signatureProvider256r1, pubKey, kid),
      // State Manager
      new RemoteManager(),
      new StatusVcDataProvider(
        {
          type: 'StatusList2021',
          statusList,
          listId,
        },
        statusPurpose,
      ),
      contexts,
    );
  }

  /**
   * Allow to compare two arrays to determine if they contains the same data
   * @param arr1 One of the arrays to compare
   * @param arr2 One of the arrays to compare
   * @returns True if both array contains the same element and have the same length
   */
  arraysContainSameStrings(arr1: string[], arr2: string[]): boolean {
    if (arr1.length !== arr2.length) {
      return false;
    }
    return arr1.every(item => arr2.includes(item));
  }

  /**
   * Allows to get the credential type apart from
   *  VerifiableAttestation and VerifiableCredential
   * @param types All the types of the credential
   * @returns A single type of a credential
   */
  getVcSpecificType(types: string[]): string {
    const result = types.find(type => {
      return (
        type !== VERIFIABLE_ATTESTATION_TYPE &&
        type !== VERIFIABLE_CREDENTIAL_TYPE &&
        type !== VERIFIABLE_ACCREDITATION_TYPE
      );
    });
    if (!result) {
      throw new HttpError(
        CredentialErrorCodes.UNSUPPROTED_CREDENTIAL_TYPE.httpStatus,
        CredentialErrorCodes.UNSUPPROTED_CREDENTIAL_TYPE.code,
        `Types ${types} are not supported`,
      );
    }
    return result;
  }

  getIssuerOfControlProof(controlProof: BaseControlProof): string {
    const proof = ControlProof.fromJSON(controlProof);
    return proof.getAssociatedIdentifier();
  }
}
