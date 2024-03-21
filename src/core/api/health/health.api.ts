import { autoInjectable, singleton } from "tsyringe";
import { Request, Response } from "express";

@singleton()
@autoInjectable()
export default class HealthApi {
  constructor() { }

  health = async (req: Request, res: Response) => {
    return res.status(200);
  };
}
