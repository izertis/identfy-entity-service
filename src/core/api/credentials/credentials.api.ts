import { Request, Response } from "express";
import { autoInjectable, singleton } from "tsyringe";
import {
  IBasicCredential_req,
  ICredential_req
} from "../../../shared/interfaces/credentials.interface.js";
import Logger from "../../../shared/classes/logger.js";
import { UnauthorizedError } from "../../../shared/classes/errors.js";
import CredentialsService from "../../services/credentials/credentials.service.js";

@singleton()
@autoInjectable()
export default class CredentialsApi {
  constructor(private credentialsService: CredentialsService, private logger: Logger) { }

  credentialRequest = async (req: Request, res: Response) => {
    this.logger.info("Credential request received...");
    const bearer = req.headers.authorization;
    if (!bearer) throw new UnauthorizedError(
      "No access token provided",
      "unauthorized_client"
    );
    const {
      issuerUri,
      issuerDid,
      privateKeyJwk,
      publicKeyJwk,
      ...request
    } = res.locals.validatedBody as ICredential_req;
    const { status, ...response } = await this.credentialsService.issueCredential(
      bearer.replace(/BEARER|\s/g, ""), // remove BEARER and " " spaces
      request,
      issuerUri,
      issuerDid,
      privateKeyJwk,
      publicKeyJwk,
    );
    this.logger.info("✅ Returning Credential response");
    return res.status(status).json(response);
  };

  deferredCredentialRequest = async (req: Request, res: Response) => {
    this.logger.info("Deferred Credential request received...");
    const bearer = req.headers.authorization;
    if (!bearer) throw new UnauthorizedError(
      "No access token provided",
      "unauthorized_client"
    );
    const {
      issuerUri,
      issuerDid,
      privateKeyJwk,
      publicKeyJwk,
    } = res.locals.validatedBody as IBasicCredential_req;
    const { status, ...response } = await this.credentialsService.issueDeferredCredential(
      bearer.replace(/BEARER|\s/g, ""), // remove BEARER and " " spaces
      issuerUri,
      issuerDid,
      privateKeyJwk,
      publicKeyJwk,
    );
    this.logger.info("✅ Returning Deferred Credential response");
    return res.status(status).json(response);
  }
}
