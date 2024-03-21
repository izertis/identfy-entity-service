import { autoInjectable, delay, inject, singleton } from "tsyringe";
import { Application } from "express";
import { BaseRouter } from "../../../shared/interfaces/api.interface.js";
import AuthApi from "./auth.api.js";
import AuthSchema from "./auth.schema.js";
import ApiUtils from "../../../shared/utils/api.utils.js";
import {
  IAuthConfig_req,
  IAuthorizeCustom_req,
  IDirectPost_req,
  IToken_req,
} from "../../../shared/interfaces/auth.interface.js";

@singleton()
@autoInjectable()
export default class AuthRouter extends BaseRouter {
  constructor(
    @inject(delay(() => ApiUtils)) private apiUtils: ApiUtils,
    // private apiUtils: ApiUtils,
    private authApi: AuthApi,
    private authSchema: AuthSchema
  ) {
    super(apiUtils, "auth");
  }

  loadRoutes(app: Application): void {
    this.router
      .route("/.well-known/openid-configuration")
      .get(
        this.validateRequestParams<IAuthConfig_req>(this.authSchema.getConfiguration, "query"),
        this.executeHandler(this.authApi.getConfiguration)
      );

    this.router
      .route("/authorize/")
      .get(
        this.validateRequestParams<IAuthorizeCustom_req>(this.authSchema.authorize, "query"),
        this.executeHandler(this.authApi.authorize)
      );

    this.router
      .route("/direct_post")
      .post(
        this.validateRequestParams<IDirectPost_req>(this.authSchema.directPost, "body"),
        this.executeHandler(this.authApi.directPost)
      );

    this.router
      .route("/token")
      .post(
        this.validateRequestParams<IToken_req>(this.authSchema.token, "body"),
        this.executeHandler(this.authApi.grantAccessToken)
      );

    app.use(this.path, this.router);
  }
}
