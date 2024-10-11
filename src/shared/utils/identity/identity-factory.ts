import { Identity } from "./identity";
import {
    DidKeyIdentity,
    DIDKEY_DID_METHOD
} from "../ebsi/identity/did-key-identity";
import {
    DIDEBSI_DID_METHOD,
    DidEbsiIdentity
} from "../ebsi/identity/did-ebsi-identity";

export class IdentityFactory {
    static create(didUrl: string): Identity {
        switch (getDidMethod(didUrl)) {
            case DIDKEY_DID_METHOD: {
                return DidKeyIdentity.fromDidUrl(didUrl);
            }
            case DIDEBSI_DID_METHOD: {
                return DidEbsiIdentity.fromDidUrl(didUrl);
            }
            default: {
                throw new Error("Unknown DID Method: " + didUrl);
            }
        }
    }
}

function getDidMethod(didUrl: string): string {
    const did = didUrl.split("?")[0];
    const parsed = did.split(":");
    return parsed[1];
}