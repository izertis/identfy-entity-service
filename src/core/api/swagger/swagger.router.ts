import { Application } from 'express';
import { autoInjectable, singleton } from "tsyringe";
import { serve, setup } from 'swagger-ui-express';
import { BaseRouter } from '../../../shared/interfaces/api.interface';
import ApiUtils from '../../../shared/utils/api.utils.js';
import YAML from "yamljs";

@singleton() @autoInjectable()
export default class SwaggerRouter extends BaseRouter {

  swaggerFile = `${process.env.appRoot}/swagger.yaml`;
  swaggerDocument = YAML.load(this.swaggerFile);

  constructor(
    private readonly apiUtils: ApiUtils
  ) {
    super(apiUtils, 'docs');
  }

  loadRoutes(app: Application): void {
    this.router.use('/', serve);
    this.router.get('/', setup(this.swaggerDocument));
    app.use(this.path, this.router);
  }

}
