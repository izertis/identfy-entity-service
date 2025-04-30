import 'core-js/features/reflect/index.js';
import 'dotenv/config';
import {container} from 'tsyringe';
import express from 'express';
import morgan from 'morgan';
import helmet from 'helmet';
import cors from 'cors';
import fileUpload from 'express-fileupload';
import Logger from './shared/classes/logger.js';
import Translator from './shared/classes/translator.js';
import OpenApiValidator from 'express-openapi-validator';
import ApiUtils from './shared/utils/api.utils.js';
import {SERVER} from './shared/config/configuration.js';
import './shared/classes/timemachine.js';
import * as url from './shared/utils/url.utils.js';
import {OPENAPI_FILE, OPENAPI_PATH} from './core/api/swagger/swagger.router.js';

const app = express();
app.use(express.json({limit: SERVER.request_size_limit}));
app.use(express.urlencoded({limit: SERVER.request_size_limit, extended: true}));
app.use(helmet());
app.use(morgan('dev'));
app.use(fileUpload());
app.use(cors({origin: true, credentials: true}));
app.use(
  OpenApiValidator.middleware({
    apiSpec: OPENAPI_FILE,
    validateRequests: true,
    validateResponses: true,
    ignorePaths: (path: string) =>
      path.startsWith(url.join(SERVER.api_path, OPENAPI_PATH)),
  }),
);

await (async (application: express.Application) => {
  container.resolve(Logger);
  container.resolve(Translator);
  await container.resolve(ApiUtils).init(application);
})(app);

// Default route to OpenAPI
app.get('', (req, res) => {
  res.redirect(url.join(SERVER.api_path, OPENAPI_PATH));
});
