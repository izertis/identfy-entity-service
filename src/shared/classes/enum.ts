export abstract class EnumType<T> {
  constructor(public key: string, public value: T) { }
  toString() {
    return this.key;
  }
}
