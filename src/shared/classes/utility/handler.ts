import {Result} from './result.js';

class MutableReference<T> {
  constructor(
    private obj: Record<string, T>,
    private key: string,
  ) {}

  get value() {
    return this.obj[this.key];
  }

  set value(data: T) {
    this.obj[this.key] = data;
  }
}

export abstract class ChainHandler {
  abstract handle(...args: any[]): Result<null, Error>;
}

export abstract class AsyncChainHandler {
  abstract handle(...args: any[]): Promise<void>;
}

export abstract class HandlerWithContext extends AsyncChainHandler {
  abstract handle(context: Context, ...args: any[]): Promise<void>;
}

export class Context {
  constructor() {
    this.memory = Object.create(null);
  }
  protected memory: Record<string, any>;

  getMut<T>(id: string): MutableReference<T> | undefined {
    if (this.memory[id] === undefined) {
      return undefined;
    }
    return new MutableReference(this.memory, id);
  }

  getMutOrThrow<T>(id: string): MutableReference<T> {
    if (this.memory[id] === undefined) {
      throw new Error(`Undefined variable ${id}`);
    }
    return new MutableReference(this.memory, id);
  }

  get<T>(id: string): T | undefined {
    return this.memory[id];
  }

  getOrThrow<T>(id: string): T {
    if (!this.memory[id]) {
      throw new Error(`Undefined variable ${id}`);
    }
    return this.memory[id];
  }

  set(id: string, data: any) {
    this.memory[id] = data;
  }

  static fromObject(data: Record<string, any>) {
    const result = new Context();
    result.memory = Object.create(data);
    return result;
  }
}
