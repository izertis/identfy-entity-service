import { Application, NextFunction, Request, Response } from "express";
import { Schema } from "joi";
import { autoInjectable, singleton } from "tsyringe";
import { HttpError } from "../classes/errors.js";
import Translator from "../classes/translator.js";
import { BaseRouter, ParamPlace } from "../interfaces/api.interface.js";
import Logger from "../classes/logger.js";
import { LANGUAGE, SERVER } from "../config/configuration.js";
import pkg from "http-status";
import { QueryFilter, QueryPagination } from "../classes/query.js";
import { readdirSync } from "fs";

const { INTERNAL_SERVER_ERROR, OK } = pkg;
@singleton()
@autoInjectable()
export default class ApiUtils {
  constructor(private logger: Logger, private translator: Translator) { }

  init = async (app: Application) => {
    this.configureMiddlewares(app);
    await this.loadApplicationRoutes(app);
    this.setErrorHandler(app);
    this.startServer(app);
  };

  private loadApplicationRoutes = async (app: Application): Promise<void> => {
    const dirents = Array.from(readdirSync(process.env.apiRoot as string, { withFileTypes: true }))
      .filter((dirent) => dirent.isDirectory())
      .map((folder) => folder.name);

    for (const folder of dirents) {
      const RouterClass = await import(`${process.env.apiRoot}/${folder}/${folder}.router`);

      if (!RouterClass.default) {
        this.logger.warn(`Router not found inside '${folder}.router.ts' file`);
        this.logger.warn(`Router will not load routes from module ${folder}`);
        continue;
      }
      if (!(RouterClass.default.prototype instanceof BaseRouter)) {
        this.logger.warn(`Router inside '${folder}Router.ts' needs to extend BaseRouter class`);
        this.logger.warn(
          `It is required to implement router class extending base router for routing`
        );
        continue;
      }
      new RouterClass.default().loadRoutes(app);
    }
  };

  private startServer = (app: Application): void => {
    const port = SERVER.port;
    this.logger.info("Starting server");
    app.listen(port, () => this.logger.info(`Server started listening in port ${port}`));
  };

  private configureMiddlewares = (app: Application) =>
    app.use((req: Request, res: Response, next: NextFunction) => {
      res.locals.language = (req.header("Accept-Language") as string) || LANGUAGE.default;
      next();
    });

  private setErrorHandler = (app: Application) =>
    app.use((err: HttpError, req: Request, res: Response, next: NextFunction) => {
      const message = this.translator.translate(err.message, res.locals.language);
      this.logger.error(message);
      this.logger.error(err.stack);

      const status = err.status || INTERNAL_SERVER_ERROR;
      return res.status(status).json({
        error: err.code ?? "internal_server_error",
        error_description: err.message
      });
    });

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  validateSchema =
    <I>(schema: Schema, place: ParamPlace): any =>
      (req: Request, res: Response, next: NextFunction) => {
        // seletct parameters to validate
        let parameters = req.body;
        switch (place.toLowerCase()) {
          case "param":
            parameters = req.params;
            break;
          case "query":
            parameters = req.query;
            break;
          default:
            parameters = req.body;
            break;
        }
        const { error, value } = schema.validate(parameters, {
          abortEarly: false,
          allowUnknown: true,
          stripUnknown: true,
        });
        if (error) {
          const details = error.details;
          const label = details[0].context?.label || "";

          const root = schema.$_terms.metas[0]?.root;
          if (!root) this.logger.warn("Schema translate root not found after validation");

          const message = root && label ? `${root}.${label}` : details[0].message;
          this.logger.log(message);
          throw new HttpError(
            400,
            "invalid_request",
            `Invalid parameters: ${message}`
          );
        }
        this.logger.log(
          `HTTP request parameters checked. Place: ${place}, Parameter: ${JSON.stringify(parameters)}`
        );
        switch (place.toLowerCase()) {
          case "param":
            res.locals.validatedParams = value as I;
            break;
          case "query":
            res.locals.validatedQuery = value as I;
            break;
          default:
            res.locals.validatedBody = value as I;
            break;
        }
        next();
      };

  processQueryParams = (strict: boolean) => (req: Request, res: Response, next: NextFunction) => {
    res.locals.pagination = new QueryPagination(req.query, strict);
    res.locals.filter = QueryFilter.createFromObject(req.query);
    next();
  };

  logAppVersion = (warning: boolean) => (req: Request, res: Response, next: NextFunction) => {
    const version = req.header("Application-Version");

    if (!version && warning) {
      this.logger.warn("Missing application version");
      return next();
    }
    this.logger.info(version);
    next();
  };

  pingServer = () => (req: Request, res: Response) => res.status(OK).json({ status: "UP" });
}

/**
 * Converts an error object to a string representation.
 *
 * @param error - The error object to convert.
 * @returns The string representation of the error.
 */
export const errorToString = (error: unknown): string => {
  if (typeof error === "string") {
    return error.toUpperCase();
  } else if (error instanceof Error) {
    return error.message;
  }
  // If the error is not a string or an instance of Error, return empty string
  return "";
};

/**
 * Checks if a given string is a valid OpenID URL.
 * @param input The string to check.
 * @returns true if the input string is a valid OpenID URL, false otherwise.
 */
export const isOpenidOrHttpUrl = (input: string) => {
  if (input.startsWith("openid://")) {
    return true;
  }
  var pattern = new RegExp(
    "^(openid|https?|http)://" + // protocol: "openid", "https", or "http"
    "((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.)+[a-z]{2,}|" + // domain name
    "((\\d{1,3}\\.){3}\\d{1,3}))" + // OR ip (v4) address
    "(:\\d+)?(/[\\w.-]*)*" + // port and path
    "(\\?[;&=\\w.-]*)?" + // query string
    "(#[-\\w_]*)?$",
    "i"
  ); // fragment locator
  return !!pattern.test(input);
};

export const removeSlash = (input: string) => {
  return input.substring(input.length - 1, input.length) === "/"
    ? input.substring(0, input.length - 1)
    : input;
};
