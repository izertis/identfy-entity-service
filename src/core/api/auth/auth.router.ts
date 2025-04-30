import {autoInjectable, delay, inject, singleton} from 'tsyringe';
import {Application} from 'express';
import {BaseRouter} from '../../../shared/interfaces/api.interface.js';
import AuthApi from './auth.api.js';
import ApiUtils from '../../../shared/utils/api.utils.js';

@singleton()
@autoInjectable()
export default class AuthRouter extends BaseRouter {
  constructor(
    @inject(delay(() => ApiUtils)) private apiUtils: ApiUtils,
    private authApi: AuthApi,
  ) {
    super(apiUtils, '/auth');
  }

  loadRoutes(app: Application): void {
    this.router
      .route('/.well-known/openid-configuration')
      .get(this.executeHandler(this.authApi.getConfiguration));
    this.router
      .route('/authorize')
      .get(this.executeHandler(this.authApi.authorize));
    this.router
      .route('/direct_post')
      .post(this.executeHandler(this.authApi.directPost));
    this.router
      .route('/token')
      .post(this.executeHandler(this.authApi.grantAccessToken));
    this.router
      .route('/presentation-offer')
      .post(this.executeHandler(this.authApi.createPresentationOffer));
    app.use(this.path, this.router);
  }
}
