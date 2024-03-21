import "core-js/features/reflect";
import "dotenv/config";
import { resolve } from "path";
import { dirname } from "path";
import { container } from "tsyringe";
import express from "express"; // eslint-disable-line import/no-unresolved
import morgan from "morgan";
import helmet from "helmet";
import cors from "cors";
import fileUpload from "express-fileupload";
import Logger from "./shared/classes/logger.js";
import Translator from "./shared/classes/translator.js";
import ApiUtils, { removeSlash } from "./shared/utils/api.utils.js";
import { SERVER } from "./shared/config/configuration.js";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet());
app.use(morgan("dev"));
app.use(fileUpload());
app.use(cors({ origin: true, credentials: true }));

process.env.appRoot = resolve(__dirname);
process.env.apiRoot = `${process.env.appRoot}/core/api`;
process.env.apiPath = `/api`;

(async (application: express.Application) => {
  container.resolve(Logger);
  container.resolve(Translator);
  await container.resolve(ApiUtils).init(application);

})(app);

// Default route
app.get("", (req, res) => {
  const env = process.env.NODE_ENV || "production";
  const url = removeSlash(req.url);
  const port = env === "local" ? SERVER.port : "80";
  res.redirect(`${req.protocol}://${req.hostname}:${port}${url}${process.env.apiPath}/docs`);
});
