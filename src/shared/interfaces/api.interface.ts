import { Application, Router } from "express";
import { Schema } from "joi";
import asyncHandler from "express-async-handler";
import ApiUtils from "../utils/api.utils.js";

export type ParamPlace = "body" | "param" | "query";

export abstract class BaseRouter {
  protected utils: ApiUtils;
  protected router: Router;
  protected path: string;

  constructor(utils: ApiUtils, path: string) {
    this.utils = utils;
    this.router = Router();
    this.path = `${process.env.apiPath}/${path}`;
  }

  public abstract loadRoutes(app: Application): void | Promise<void>;

  protected pingServer = () => this.utils.pingServer();

  protected logAppVersion = (warning: boolean) => this.utils.logAppVersion(warning);

  protected processQueryParams = (strict: boolean) => this.utils.processQueryParams(strict);

  protected validateRequestParams = <T>(schema: Schema, place: ParamPlace = "body") =>
    this.utils.validateSchema<T>(schema, place);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected executeHandler = (handler: any) => asyncHandler(handler);
}
