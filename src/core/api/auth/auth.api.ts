import { Request, Response } from "express";
import { autoInjectable, singleton } from "tsyringe";
import {
  IAuthConfig_req,
  IAuthorizeCustom_req,
  IDirectPost_req,
  IPresentationOffer_req,
  IToken_req,
} from "../../../shared/interfaces/auth.interface.js";
import Logger from "../../../shared/classes/logger.js";
import AuthService from "../../services/auth/auth.service.js";
import { AuthzRequestWithJWT } from "openid-lib";

@singleton()
@autoInjectable()
export default class AuthApi {
  constructor(private authService: AuthService, private logger: Logger) { }

  getConfiguration = async (_req: Request, res: Response) => {
    this.logger.info("Getting OIDC configuration");
    const {
      issuerUri
    } = res.locals.validatedQuery as IAuthConfig_req;
    const { status, ...response } = await this.authService.getConfiguration(issuerUri);
    this.logger.info("✅   OIDC configuration returned");
    return res.status(status).json(response);
  };

  authorize = async (_req: Request, res: Response) => {
    this.logger.info("Authorize request received");
    const {
      issuerUri,
      privateKeyJwk: privateKeyStr,
      publicKeyJwk: publicKeyStr,
      ...params
    } = res.locals.validatedQuery as IAuthorizeCustom_req;
    const { status, ...response } = await this.authService.authorize(
      issuerUri,
      privateKeyStr,
      publicKeyStr,
      params as AuthzRequestWithJWT,
    );
    this.logger.info("✅   Authorize response sent as redirection");
    this.logger.log(JSON.stringify(response));
    return res.status(status).json(response);
  };

  directPost = async (_req: Request, res: Response) => {
    const data = res.locals.validatedBody as IDirectPost_req;
    const { status, ...response } = await this.authService.directPost(
      data.issuerUri,
      data.privateKeyJwk,
      data.id_token,
      data.vp_token,
      data.presentation_submission,
    );
    this.logger.info("✅ Returning code response (Authorization Response) as redirection");
    this.logger.log(JSON.stringify(response));
    return res.status(status).json(response);
  };

  grantAccessToken = async (_req: Request, res: Response) => {
    this.logger.info("Token Request received");
    const {
      issuerUri,
      privateKeyJwk,
      publicKeyJwk,
      ...params
    } = res.locals.validatedBody as IToken_req;
    const { status, ...response } = await this.authService.grantAccessToken(
      issuerUri,
      privateKeyJwk,
      publicKeyJwk,
      params
    );
    this.logger.info("✅   Token response sent with Access Token");
    return res.set("Cache-Control", "no-store")
      .set("Pragma", "no-cache")
      .status(status)
      .json(response);
  };

  createPresentationOffer = async (_req: Request, res: Response) => {
    this.logger.info("Presentation Offer request received");
    const {
      issuerUri,
      privateKeyJwk: privateKeyStr,
      publicKeyJwk: publicKeyStr,
      verify_flow,
      state
    } = res.locals.validatedBody as IPresentationOffer_req;
    const response = await this.authService.createPresentationOffer(
      issuerUri,
      privateKeyStr,
      publicKeyStr,
      verify_flow,
      state
    );
    this.logger.info("✅   Presentation Offer Request sended");
    this.logger.log(JSON.stringify(response));
    return res.status(200).json(response);
  };

}
