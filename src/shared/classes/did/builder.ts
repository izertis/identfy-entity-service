import {DIDDocument, Resolver } from 'did-resolver';
import {KeysFromDidResolver } from './resolver.js';
import {VerificationMethodTypeResolver } from './vm_resolutor.js';
import {VerificationRelationship } from '../../../shared/types/vm.types.js';
import {InvalidConfigurationResolver } from '../error/internalerror.js';

export interface VerificationRelationshipExtraction {
  extractFromDocument: (document: DIDDocument) => string[];
}

export class KeysFromDidConfiguration {
  private vmTypeResolverMap: Record<string, VerificationMethodTypeResolver> =
    {};
  private didResolver: Resolver | undefined = undefined;
  private extractMethod: VerificationRelationshipExtraction;
  constructor(verificationRelationship: VerificationRelationship) {
    switch (verificationRelationship) {
      case 'authentication':
        this.extractMethod = new (class
          implements VerificationRelationshipExtraction {
          extractFromDocument(document: DIDDocument): string[] {
            return document.authentication as string[];
          }
        })();
        break;
      case 'assertionMethod':
        this.extractMethod = new (class
          implements VerificationRelationshipExtraction {
          extractFromDocument(document: DIDDocument): string[] {
            return document.assertionMethod as string[];
          }
        })();
        break;
      case 'capabilityDelegation':
        this.extractMethod = new (class
          implements VerificationRelationshipExtraction {
          extractFromDocument(document: DIDDocument): string[] {
            return document.capabilityDelegation as string[];
          }
        })();
        break;
      case 'capabilityInvocation':
        this.extractMethod = new (class
          implements VerificationRelationshipExtraction {
          extractFromDocument(document: DIDDocument): string[] {
            return document.capabilityInvocation as string[];
          }
        })();
        break;
      case 'keyAgreement':
        this.extractMethod = new (class
          implements VerificationRelationshipExtraction {
          extractFromDocument(document: DIDDocument): string[] {
            return document.keyAgreement as string[];
          }
        })();
        break;
    }
  }

  withDidResolver(
    didResolver: Resolver,
  ): KeysFromDidConfiguration {
    this.didResolver = didResolver;
    return this;
  }

  withVerificationMethodTypeResolutor(
    id: string,
    resolver: VerificationMethodTypeResolver,
  ): KeysFromDidConfiguration {
    this.vmTypeResolverMap[id] = resolver;
    return this;
  }

  generateInstance(): KeysFromDidResolver {
    if (!this.didResolver) {
      throw new InvalidConfigurationResolver(
        'A DID Resolver must be specified',
      );
    }
    if (!Object.keys(this.vmTypeResolverMap).length) {
      throw new InvalidConfigurationResolver(
        'At leat one Verification Method type resolver must be specify',
      );
    }
    return new KeysFromDidResolver(
      this.didResolver,
      this.extractMethod,
      this.vmTypeResolverMap,
    );
  }
}
