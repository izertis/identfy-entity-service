import EthereumHDKey from "ethereumjs-wallet/dist/hdkey";
import { Signer } from "./signer";
import { HasDidUrl } from "./has-did-url";

export abstract class Identity implements HasDidUrl {

    abstract getDid(): string;

    abstract getDidUrl(): string;

    abstract getSigner(walletIdentity: EthereumHDKey): Signer;
}
