import {keccak256} from '@ethersproject/keccak256';
import {createHash} from 'crypto';
import { HashFunctions } from '../types/hash_functions.js';

export interface Hasher {
  hash(data: string | Buffer): Buffer;
  expectedHashSyze(): number;
}

class Sha256 implements Hasher {
  expectedHashSyze(): number {
    return 32;
  }
  hash(data: string | Buffer): Buffer {
    return createHash('sha256').update(data).digest();
  }
}

class Keccak256 implements Hasher {
  expectedHashSyze(): number {
    return 32;
  }
  hash(data: string | Buffer): Buffer {
    const tmp = keccak256(data);
    return Buffer.from(tmp.slice(2), 'hex');
  }
}

export class HasherFactory {
  generateHasher(hashFunction: HashFunctions): Hasher {
    switch (hashFunction) {
      case 'sha256':
        return new Sha256();
      case 'keccak256':
        return new Keccak256();
    }
  }
}
