import {Application} from 'express';
import {autoInjectable, singleton} from 'tsyringe';
import * as swaggerui from 'swagger-ui-express';
import {BaseRouter} from '../../../shared/interfaces/api.interface.js';
import ApiUtils from '../../../shared/utils/api.utils.js';
import * as yaml from 'js-yaml';
import {SRC_DIR} from '../../../shared/utils/path.utils.js';
import fs from 'fs';

export const OPENAPI_FILE = `${SRC_DIR}/openapi.yaml`;
export const OPENAPI_PATH = '/docs';

@singleton()
@autoInjectable()
export default class SwaggerRouter extends BaseRouter {
  constructor(private readonly apiUtils: ApiUtils) {
    super(apiUtils, OPENAPI_PATH);
  }

  loadRoutes(app: Application): void {
    const openApiDocument = yaml.load(
      fs.readFileSync(OPENAPI_FILE, 'utf8'),
    ) as swaggerui.JsonObject;
    this.router.use('/', swaggerui.serve);
    this.router.get('/', swaggerui.setup(openApiDocument));
    app.use(this.path, this.router);
  }
}
