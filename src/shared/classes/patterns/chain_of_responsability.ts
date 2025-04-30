import {Stack} from '../data_structures/stack.js';
import {ChainHandler} from '../utility/handler.js';
import {Result} from '../utility/result.js';

export abstract class LazyChainOfResponsability {
  private stack: Stack<ChainHandler> = new Stack();

  addHandler(handler: ChainHandler) {
    this.stack.push(handler);
  }

  collect(input: any): Result<null, Error> {
    let item = this.stack.pop();
    while (item !== undefined) {
      const result = item.handle(input);
      if (result.isError()) {
        this.stack.clear();
        return result;
      }
      item = this.stack.pop();
    }
    return Result.Ok(null);
  }
}
