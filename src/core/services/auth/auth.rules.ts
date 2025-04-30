import {
  JWK,
  JWTPayload,
  KeyLike,
  SignJWT,
  calculateJwkThumbprint,
  importJWK,
} from 'jose';
import {P, match} from 'ts-pattern';
import fetch from 'node-fetch';
import {autoInjectable, singleton} from 'tsyringe';
import Logger from '../../../shared/classes/logger.js';
import {Resolver} from 'did-resolver';
import {getResolver as keyDidResolver} from '@cef-ebsi/key-did-resolver';
import {errorToString, removeSlash} from '../../../shared/utils/api.utils.js';
import {
  AuthServerMetadata,
  DIFPresentationDefinition,
  HolderMetadata,
  InvalidRequest,
  OpenIDReliyingParty,
  OpenIdRPStepBuilder,
  generateDefaultAuthorisationServerMetadata,
  Result,
} from 'openid-lib';
import {
  AUTHORIZATION,
  EBSI,
  VERIFIER,
} from '../../../shared/config/configuration.js';
import {
  VcScopeAction,
  VpScopeAction,
} from '../../../shared/interfaces/scope-action.interface.js';
import {BadRequestError, HttpError} from '../../../shared/classes/error/httperrors.js';
import {AuthzErrorCodes} from '../../../shared/constants/error_codes.constants.js';
import {URLSearchParams} from 'url';
import {IdentityFactory} from '../../../shared/utils/identity/identity-factory.js';
import {getResolver as ebsiDidResolver} from '@cef-ebsi/ebsi-did-resolver';
import {TokenType} from './auth.service.js';
import {
  ONBOARD_VC,
} from '../../../shared/constants/ebsi.constants.js';
import {checkCredentialStatus} from './checks/credential_status/index.js';
import {checkTrustChain} from './checks/terms_of_use/index.js';
import {RemoteManager} from '../../state/index.js';
import {getIssuanceInfo, getVerificationInfo} from '../request_info/index.js';
import {
  crvToAlg,
  keysBackend,
} from '../../../shared/utils/functions/auth.utils.js';
import {SignatureProvider} from '../../../shared/classes/signature_provider/index.js';
import {KeyFormat, PublicKeyFormat} from '../../../shared/types/keys.type.js';
import { InfallibleError } from 'src/shared/classes/error/internalerror.js';

@singleton()
@autoInjectable()
export default class AuthRules {
  constructor(private logger: Logger) {}

  didResolver = new Resolver({
    ...keyDidResolver(),
    ...ebsiDidResolver({
      registry: EBSI.did_registry,
    }),
  });

  /**
   * Generate a callback that, given a payload, generates a JWT
   * @param privateKey The private key to use
   * @param publicKeyJwk The public key related to the private key
   * @param pubKeyThumbprint The thumbprint of the public key
   * @returns A function that is able to generate JWTs
   */
  generateJwt(
    privateKey: KeyLike | Uint8Array,
    publicKeyJwk: JWK,
    pubKeyThumbprint: string,
  ) {
    return async (payload: JWTPayload, _algs: any) => {
      const header = {
        typ: 'JWT',
        alg: publicKeyJwk.alg!,
        kid: publicKeyJwk.kid || pubKeyThumbprint,
      };
      return await new SignJWT(payload)
        .setProtectedHeader(header)
        .setIssuedAt()
        .sign(privateKey);
    };
  }

  /**
   * Generate the instance of a RP
   * @param issuer The issuer identifier
   * @returns An instance of a RP
   */
  buildRp = async (
    issuer: string,
  ): Promise<OpenIDReliyingParty> => {
    let signature: SignatureProvider;
    let pubKey: JWK;
    let thumbprint: string;
    const keys_256r1 = await keysBackend(issuer, 'secp256r1');
    signature = (
      await SignatureProvider.generateProvider(
        keys_256r1.format,
        keys_256r1.type,
        keys_256r1.value,
      )
    );
    pubKey = signature.getPublicKey(PublicKeyFormat.JWK);
    thumbprint = await calculateJwkThumbprint(pubKey);

    const rp = new OpenIdRPStepBuilder({
      ...this.getIssuerMetadata(issuer),
      grant_types_supported: [
        'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'authorization_code',
      ],
    })
      .withCustomSubjectComparison((firstId, secondId) => {
        return IdentityFactory.create(firstId).isMeOrDerived(secondId);
      })
      .withVpCredentialExternalVerification(
        async (vc, _dmVersion, _issuerPublickKey?) => {
          // TODO: Modify the return type. The object is no longer needed
          let result = await checkCredentialStatus(vc);
          if (!result.valid) {
            return Result.Err(new Error(result.error!));
          }
          if (EBSI.verify_terms_of_use) {
            result = await checkTrustChain(vc);
          }
          if (!result.valid) {
            return Result.Err(new Error(result.error!));
          }
          return Result.Ok(null);
        },
      )
      .withPreAuthCallback(async (_clientId, preCode, _pin) => {
        return Result.Ok(preCode);
      })
      .setDefaultHolderMetadata(this.defaultClientMetadata())
      .withDidResolver(this.didResolver)
      .withTokenSignCallback(async (payload, _algs) => {
        const header = {
          alg: await crvToAlg(pubKey.crv!),
          kid: thumbprint,
          typ: 'JWT',
        };

        const jwt = (await signature.signJwt(header, payload));
        return jwt;
      })
      .withStateManager(new RemoteManager())
      .build();
    return rp;
  };

  verifyToken = async (
    rp: OpenIDReliyingParty,
    token: string,
    tokenType: TokenType,
    vcType?: string,
    presentationDefinition?: DIFPresentationDefinition,
    presentationSubmission?: string,
  ) => {
    if (tokenType === TokenType.ID) {
      let checkSignature = true;
      if (vcType === ONBOARD_VC) {
        // In this case, the DID Document is not yet registered in the EBSI ecosystem
        checkSignature = false;
      }
      const verifiedIdTokenResponse = await rp.verifyIdTokenResponse(
        {
          id_token: token,
        },
        checkSignature,
      );
      const holderDid = verifiedIdTokenResponse.didDocument
        ? verifiedIdTokenResponse.didDocument.id
        : verifiedIdTokenResponse.subject;
      return {
        holderDid,
        authzCode: verifiedIdTokenResponse.authzCode,
        state: verifiedIdTokenResponse.state,
        redirectUri: verifiedIdTokenResponse.redirectUri,
      };
    } else {
      if (!presentationSubmission) {
        throw new InvalidRequest('A presentation submission is needed');
      }
      const submission = JSON.parse(presentationSubmission); // TODO: Check schema?
      this.logger.info('Verify VP Token');
      const verifiedVpTokenResponse = await rp.verifyVpTokenResponse(
        {
          vp_token: token,
          presentation_submission: submission,
        },
        presentationDefinition!,
        // TODO: CONSIDER ADDING A ENV TO CONTROL THE SIGNATURE CHECKING
      );
      return {
        holderDid: verifiedVpTokenResponse.vpInternalData.holderDid,
        claimsData: verifiedVpTokenResponse.vpInternalData.claimsData,
        authzCode: verifiedVpTokenResponse.authzCode,
        state: verifiedVpTokenResponse.state,
        redirectUri: verifiedVpTokenResponse.redirectUri,
      };
    }
  };

  getScopeAction = async (
    entityUri: string,
    nonce: string,
  ): Promise<VcScopeAction | VpScopeAction> => {
    const remoteManager = new RemoteManager();
    const state: any = await remoteManager.getState(nonce);
    if (!state) {
      throw new BadRequestError(
        'Invalid nonce specified',
        AuthzErrorCodes.INVALID_REQUEST,
      );
    }
    const scopeAction = await match(state.operationType)
      .with(
        {type: 'Issuance', vcTypes: {type: 'Know', vcTypes: P.select()}},
        async vcTypes => {
          return await getIssuanceInfo(entityUri, vcTypes as string[]);
        },
      )
      .with({type: 'Verification', scope: P.select()}, async scope => {
        return await getVerificationInfo(entityUri, scope as string);
      })
      .otherwise(() => {
        // This is an infallible error
        throw new InfallibleError(
          'This should not happen',
          AuthzErrorCodes.INVALID_REQUEST,
        );
      });
    return scopeAction;
  };

  /**
   * Allows to generate an error to be used in a redirect response.
   *
   * @param uri The redirect URI.
   * @param code The error identifier code.
   * @param description The error description.
   * @returns The HTTP Status to use among the location to use with the error
   */
  generateLocationErrorResponse = (
    uri: string,
    code: string,
    description: string,
    state?: string,
  ) => {
    const params: Record<string, any> = {
      error_description: description,
      error: code,
    };
    if (state) {
      params.state = state;
    }
    return {
      status: 302,
      location: this.buildRedirectResponse(
        uri,
        new URLSearchParams(params).toString(),
      ),
    };
  };

  /**
   * Allows to generate a HTTP location.
   *
   * @param redirectUri The redirect URI.
   * @param params The params to concatenate in the URI.
   * @returns The location URI to use
   */
  buildRedirectResponse = (redirectUri: string, params: string): string => {
    const hasParams = redirectUri!.includes('?');
    const redirect_uri = hasParams
      ? redirectUri
      : redirectUri?.endsWith('/')
        ? redirectUri
        : `${redirectUri}/`;
    return `${redirect_uri}${hasParams ? '&' : '/?'}${params}`;
  };

  /**
   * Parses private and public keys in JWK format.
   *
   * @param privateKeyStr - Optional. The private key string in JWK format.
   * @param publicKeyStr - Optional. The public key string in JWK format.
   * @returns An object containing the parsed JWK and key-like representations of the private and public keys.
   * @throws Error if at least one key is not provided or if there are errors parsing the keys.
   */
  parseKeysJwk = async (
    privateKeyStr?: string,
    publicKeyStr?: string,
  ): Promise<{
    jwk: {privateKey: JWK; publicKey: JWK};
    keyLike: {
      privateKey: KeyLike | Uint8Array;
      publicKey: KeyLike | Uint8Array;
    };
  }> => {
    if (!privateKeyStr && !publicKeyStr) {
      throw new Error('At lest one key must be provided');
    }
    let privateKeyJwk: JWK;
    let privateKey: KeyLike | Uint8Array;
    let publicKeyJwk: JWK;
    let publicKey: KeyLike | Uint8Array;
    if (privateKeyStr) {
      try {
        privateKeyJwk = JSON.parse(privateKeyStr!);
        privateKey = await importJWK(privateKeyJwk);
      } catch (error) {
        this.logger.error(errorToString(error));
        throw new Error(`Parsing private key to JWK object. ${error}`);
      }
    }
    if (publicKeyStr) {
      try {
        publicKeyJwk = JSON.parse(publicKeyStr!);
        publicKey = await importJWK(publicKeyJwk);
      } catch (error) {
        throw new Error(`Parsing public key to JWK object. ${error}`);
      }
    } else if (privateKeyStr) {
      publicKeyJwk = {...privateKeyJwk!};
      delete publicKeyJwk.d;
      publicKey = await importJWK(publicKeyJwk);
    }

    return {
      jwk: {privateKey: privateKeyJwk!, publicKey: publicKeyJwk!},
      keyLike: {privateKey: privateKey!, publicKey: publicKey!},
    };
  };

  /**
   * Get issuer metadata configuration based on trust framework
   * @param issuer
   * @returns
   */
  getIssuerMetadata(issuer: string) {
    return this.ebsiAuthorisationServerMetadata(issuer)
  }

  /**
   * Generate metadata configuration for a Issuer according to EBSI
   * @param issuer The issuer identifier. It should be an URI
   * @returns Authorisation server metadata
   */
  ebsiAuthorisationServerMetadata(issuerUri: string): AuthServerMetadata {
    // Remove "/" if it comes set in the parameter
    issuerUri = removeSlash(issuerUri);
    // Destructure the AUTHORIZATION object
    const {issuer, authorization_endpoint, token_endpoint, jwks_uri} =
      AUTHORIZATION;

    const defaultValue = generateDefaultAuthorisationServerMetadata(issuerUri);

    return {
      ...defaultValue,
      issuer: issuerUri.concat(issuer),
      authorization_endpoint: issuerUri.concat(authorization_endpoint),
      token_endpoint: issuerUri.concat(token_endpoint),
      jwks_uri: issuerUri.concat(jwks_uri),
      grant_types_supported: [
        'authorization_code',
        'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      ],
    };
  }

  /**
   * Generate the default IClientMetadata
   * @returns The default IClientMetadata
   */
  private defaultClientMetadata = (): HolderMetadata => {
    return {
      authorization_endpoint: 'openid:',
      vp_formats_supported: {
        jwt_vp: {
          alg_values_supported: ['ES256'],
        },
        jwt_vc: {
          alg_values_supported: ['ES256'],
        },
      },
      response_types_supported: ['vp_token', 'id_token'],
      scopes_supported: ['openid'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['ES256'],
      request_object_signing_alg_values_supported: ['ES256'],
      subject_syntax_types_supported: [
        'urn:ietf:params:oauth:jwk-thumbprint',
        'did:key:jwk_jcs-pub',
      ],
      id_token_types_supported: ['subject_signed_id_token'],
    };
  };

  /**
   * Verify the direct post request on verifier external data endpoint
   * @param valid token is valid
   * @param verifierUri The URI of the issuer
   * @param holderDid Holder DID
   * @param claimsData The data that has be verified
   * @param state State included on token
   * @returns Confirmation of the validity of the provided data
   */
  verifyOnExternalData = async (
    valid: boolean,
    verifierUri: string,
    state?: string,
    holderDid?: string,
    claimsData?: Record<string, unknown>,
  ): Promise<{verified: boolean}> => {
    try {
      const data = {
        valid,
        ...(holderDid && {holderDid}),
        ...(claimsData && {claimsData}),
        ...(state && {state}),
      };
      const fetchResponse = await fetch(
        `${verifierUri}${VERIFIER.vp_verification_endpoint}`,
        {
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(data),
          method: 'post',
        },
      );
      if (fetchResponse.status !== 200) {
        this.logger.error(
          `An error ocurred requesting VC data: ${fetchResponse.statusText}`,
        );
        throw new HttpError(
          500,
          AuthzErrorCodes.SERVER_ERROR,
          `Error requesting VP data verification`,
        );
      }
      if (
        fetchResponse.headers.get('Content-Type') !== 'application/json' &&
        fetchResponse.headers.get('content-type') !== 'application/json'
      ) {
        this.logger.error(`VP data verification response not in JSON format`);
        throw new HttpError(
          500,
          AuthzErrorCodes.SERVER_ERROR,
          `Error requesting VP data verification`,
        );
      }
      return (await fetchResponse.json()) as {verified: boolean};
    } catch (error: any) {
      if (error instanceof HttpError) {
        throw error;
      }
      this.logger.error(`GET VP VERIFICATION ERROR: ${error.message}`);
      throw new HttpError(
        500,
        AuthzErrorCodes.SERVER_ERROR,
        'Error requesting VP data verification',
      );
    }
  };
}
