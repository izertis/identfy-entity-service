import {autoInjectable, singleton} from "tsyringe";
import {RpcHandler} from "./rpc_handler.js";
import Logger from "../../../shared/classes/logger.js";
import {
  RpcMethod,
  RpcResponse
} from "../../../shared/interfaces/rpc.interface.js";
import {
  RpcError,
  RpcInternalError,
  RpcInvalidParams,
  RpcMethodNotFound
} from "../../../shared/classes/error/rpc.error.js";
import RpcSchema from "../../../shared/schemas/rpc.schemas.js";
import {
  ExecutionFailed,
  InvalidParameters
} from "src/shared/classes/error/internalerror.js";

@singleton()
@autoInjectable()
export default class RpcService {
  constructor(private logger: Logger, private rpcSchema: RpcSchema) { }
  proccessRpcMethod = async (method: RpcMethod) => {
    const rpcHandler = new RpcHandler(this.rpcSchema);
    let result: any;
    try {
      this.logger.log("Processing RPC method");
      switch (method.method) {
        case "onboardDid":
          result = await rpcHandler.onboardDid(method);
          break;
        case "addVerificationMethod":
          result = await rpcHandler.addVerificationMethod(method);
          break;
        case "addVerificationRelationship":
          result = await rpcHandler.addVerificationRelationship(method);
          break;
        case "addTrustedIssuer":
          result = await rpcHandler.addTrustedIssuer(method);
          break;
        case "revokeAccreditation":
          result = await rpcHandler.revokeAccreditation(method);
          break;
        case "setTrustedIssuerData":
          result = await rpcHandler.setTrustedIssuerData(method);
          break;
        case "resolveCredentialOffer":
          result = await rpcHandler.resolveCredentialOffer(method);
          break;
        case "requestVC":
          result = await rpcHandler.requestVc(method);
          break;
        case "requestVcWithUri":
          result = await rpcHandler.requestVcWithURI(method);
          break;
        case "requestDeferredVC":
          result = await rpcHandler.requestDeferredVc(method);
          break;
        case "addIssuerProxy":
          result = await rpcHandler.addIssuerProxy(method);
          break;
        default:
          throw new RpcMethodNotFound();
      }
    } catch (error: any) {
      if (error instanceof RpcError) {
        let code;
        switch (error.message) {
          case "Method not found":
            code = 404;
            break;
          case "Invalid Request":
          case "Invalid params":
            code = 400;
            break;
          case "Internal error":
          case "Parse Error":
          case "Server error":
            code = 500;
            break;
        }
        const response = generateRpcErrorResponse(error, method.id);
        return { status: code, ...response };
      } else if (error instanceof ExecutionFailed) {
        const response = generateRpcErrorResponse(
          new RpcInternalError(error.message),
          method.id
        );
        return { status: 500, ...response };
      } else if (error instanceof InvalidParameters) {
        const response = generateRpcErrorResponse(
          new RpcInvalidParams(error.message),
          method.id
        );
        return { status: 400, ...response };
      }
      throw error;
    }
    this.logger.log("RPC Method has finished execution");
    return { status: 200, ...generateRpcOkResponse(result, method.id) };
  }
}

function generateRpcOkResponse(data: any, id?: string): RpcResponse {
  const result: RpcResponse = {
    jsonrpc: "2.0",
    result: data,
  };
  if (id) {
    result.id = id;
  };
  return result;
}

function generateRpcErrorResponse(
  error: RpcError,
  id?: string
): RpcResponse {
  const result: RpcResponse = {
    jsonrpc: "2.0",
    error: error,
  };
  if (id) {
    result.id = id;
  };
  return result;
}
