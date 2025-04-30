import {Resolver} from 'did-resolver';
import {VerificationRelationshipExtraction} from './builder.js';
import {VerificationMethodTypeResolver} from './vm_resolutor.js';
import {SignatureProvider} from '../signature_provider/index.js';
import {DidResolutionError} from '../error/internalerror.js';
import {publicJwkToDer} from '../../../shared/utils/der.utils.js';
import {PublicKeyFormat} from '../../../shared/types/keys.type.js';

export class KeysFromDidResolver {
  constructor(
    private didResolver: Resolver,
    private extractMethod: VerificationRelationshipExtraction,
    private vmTypeResolverMap: Record<string, VerificationMethodTypeResolver>,
  ) {}

  async compareKeyWithDidDocumentsKeys(
    did: string,
    keyToCompare: SignatureProvider,
  ): Promise<string> {
    const didDocumentResolution = await this.didResolver.resolve(did);
    if (!didDocumentResolution.didDocument) {
      throw new DidResolutionError('DID not found');
    }
    const idsForRelationships = this.extractMethod.extractFromDocument(
      didDocumentResolution.didDocument,
    );
    // Retrieve the keys from the VM
    const filteredVMs =
      didDocumentResolution.didDocument.verificationMethod!.filter(vm => {
        return idsForRelationships.includes(vm.id);
      });
    if (!filteredVMs.length) {
      throw new DidResolutionError(
        'DID Document is bad formatted. No Verification Methods defined',
      );
    }
    const jwkKey = await keyToCompare.getPublicKey(PublicKeyFormat.JWK);
    const localKeyDer = publicJwkToDer(jwkKey);
    for (const vm of filteredVMs) {
      const vmResolver = this.vmTypeResolverMap[vm.type];
      if (!vmResolver) {
        throw new DidResolutionError(
          'DID Document is bad formatted. No Verification Methods defined',
        );
      }
      const documentKeyDer = vmResolver.toDer(vm);
      if (Buffer.compare(localKeyDer, documentKeyDer) === 0) {
        return vm.id;
      }
    }
    throw new Error('No Key in the DID Document is equal to the provided key'); // TODO: Custom error
  }
}
