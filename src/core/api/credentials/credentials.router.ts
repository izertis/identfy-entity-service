import { autoInjectable, singleton } from 'tsyringe';
import { Application } from 'express';
import { BaseRouter } from '../../../shared/interfaces/api.interface.js';
import CredentialsApi from './credentials.api.js';
import ApiUtils from '../../../shared/utils/api.utils.js';

@singleton()
@autoInjectable()
export default class CredentialsRouter extends BaseRouter {
  constructor(
    private apiUtils: ApiUtils,
    private credentialsApi: CredentialsApi,
  ) {
    super(apiUtils, '');
  }

  loadRoutes(app: Application): void {
    this.router
      .route('/credentials')
      .post(this.executeHandler(this.credentialsApi.credentialRequest));

    this.router
      .route('/credential_deferred')
      .post(this.executeHandler(this.credentialsApi.deferredCredentialRequest));
    this.router
      .route('/credentials/status')
      .post(this.executeHandler(this.credentialsApi.statusCredentialRequest));
    this.router
      .route('/ebsi/accreditation/issuance')
      .get(
        this.executeHandler(
          this.credentialsApi.ebsiAccreditationDirectIssuance,
        ),
      );
    app.use(this.path, this.router);
  }
}
