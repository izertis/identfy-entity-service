import {Application, Router} from 'express';
import asyncHandler from 'express-async-handler';
import ApiUtils from '../utils/api.utils.js';
import * as url from '../utils/url.utils.js';
import {SERVER} from '../config/configuration.js';

export type ParamPlace = 'body' | 'param' | 'query';

export abstract class BaseRouter {
  protected utils: ApiUtils;
  protected router: Router;
  protected path: string;

  constructor(utils: ApiUtils, additionalPath: string) {
    this.utils = utils;
    this.router = Router();
    this.path = url.join(SERVER.api_path, additionalPath);
  }

  public abstract loadRoutes(app: Application): void | Promise<void>;

  protected pingServer = () => this.utils.pingServer();

  protected logAppVersion = (warning: boolean) =>
    this.utils.logAppVersion(warning);

  protected processQueryParams = (strict: boolean) =>
    this.utils.processQueryParams(strict);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected executeHandler = (handler: any) => asyncHandler(handler);
}
