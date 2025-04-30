import { Request, Response } from "express";
import RpcService from "../../services/rpc/rpc.service.js";
import { autoInjectable, singleton } from "tsyringe";

@singleton()
@autoInjectable()
export default class RpcApi {
  constructor(private rpcService: RpcService) { }

  processRpcMethod = async (req: Request, res: Response) => {
    const { status, ...response } = await this.rpcService.proccessRpcMethod(
      req.body
    );
    return res.status(status).json(response);
  };
}
