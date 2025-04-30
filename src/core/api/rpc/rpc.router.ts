import { autoInjectable, singleton } from "tsyringe";
import { Application } from "express";
import RpcApi from "./rpc.api.js";
import ApiUtils from "../../../shared/utils/api.utils.js";
import { BaseRouter } from "src/shared/interfaces/api.interface.js";

@singleton()
@autoInjectable()
export default class RpcRouter extends BaseRouter {
  constructor(
    private apiUtils: ApiUtils,
    private rpcApi: RpcApi,
  ) {
    super(apiUtils, "");
    this.path = "/rpc"
  }

  loadRoutes(app: Application): void {
    this.router
      .route("")
      .post(
        this.executeHandler(this.rpcApi.processRpcMethod)
      );
    app.use(this.path, this.router);
  }
}
