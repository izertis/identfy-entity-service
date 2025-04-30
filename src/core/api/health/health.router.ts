import {Application} from 'express';
import {autoInjectable, singleton} from 'tsyringe';
import {BaseRouter} from '../../../shared/interfaces/api.interface.js';
import ApiUtils from '../../../shared/utils/api.utils.js';
import HealthApi from './health.api.js';

@singleton()
@autoInjectable()
export default class HealthRouter extends BaseRouter {
  constructor(
    private apiUtils: ApiUtils,
    private healthApi: HealthApi,
  ) {
    super(apiUtils, '/system');
  }

  loadRoutes(app: Application): void {
    this.router
      .route('/health')
      .get(this.executeHandler(this.healthApi.health));
    app.use(this.path, this.router);
  }
}
