import { autoInjectable, singleton } from "tsyringe";
import { Application } from "express";
import { BaseRouter } from "../../../shared/interfaces/api.interface.js";
import CredentialsApi from "./credentials.api.js";
import CredentialsSchema from "./credentials.schema.js";
import ApiUtils from "../../../shared/utils/api.utils.js";
import {
  ICredential_req, IStatusCredentialRequest
} from "../../../shared/interfaces/credentials.interface.js";

@singleton()
@autoInjectable()
export default class CredentialsRouter extends BaseRouter {
  constructor(
    private apiUtils: ApiUtils,
    private credentialsApi: CredentialsApi,
    private credentialsSchema: CredentialsSchema
  ) {
    super(apiUtils, "");
  }

  loadRoutes(app: Application): void {
    this.router
      .route("/credentials")
      .post(
        this.validateRequestParams<ICredential_req>(
          this.credentialsSchema.credentialRequest.body,
          "body"
        ),
        this.executeHandler(this.credentialsApi.credentialRequest)
      );

    this.router
      .route("/credential_deferred")
      .post(
        this.validateRequestParams<ICredential_req>(
          this.credentialsSchema.deferredCredential.body,
          "body"
        ),
        this.executeHandler(this.credentialsApi.deferredCredentialRequest)
      )
    this.router
      .route("/credentials/status")
      .post(
        this.validateRequestParams<IStatusCredentialRequest>(
          this.credentialsSchema.statusCredential.body, "body"
        ),
        this.executeHandler(this.credentialsApi.statusCredentialRequest)
      )
    app.use(this.path, this.router);
  }
}
