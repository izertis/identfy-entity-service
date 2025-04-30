import { ErrorMessagesType } from "../../../shared/types/rpc.types.js";

export class RpcError extends Error {
  constructor(
      public code: number,
      public message: ErrorMessagesType,
      public data?: string,
  ) {
      super(message);
  }
}

export class RpcMethodNotFound extends RpcError {
  constructor(
      public data?: string,
  ) {
      super(-32601, "Method not found", data);
  }
}

export class RpcInternalError extends RpcError {
  constructor(
      public data?: string,
  ) {
      super(-32603, "Internal error", data);
  }
}

export class RpcInvalidParams extends RpcError {
  constructor(
      public data?: string,
  ) {
      super(-32602, "Invalid params", data);
  }
}
