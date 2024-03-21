/* eslint-disable @typescript-eslint/no-explicit-any */
import { singleton } from "tsyringe";
import { existsSync, mkdirSync } from "fs";
import { dirname, join, resolve } from "path";
import { createLogger, transport, transports, format, Logger as WistonLogger } from "winston";
import { LOGS } from "../config/configuration.js";

@singleton()
export default class Logger {
  private logger!: WistonLogger;

  private format = format.printf((info) => {
    let { timestamp, level, message } = info;
    return `[${timestamp}] [${level}]: ${message}`;
  });

  constructor() {
    this.init();
  }

  private createLogTransports = () => {
    const { console, file } = LOGS;
    const logTransports: transport[] = [];

    if (console.active) {
      logTransports.push(
        new transports.Console({
          level: console.level,
          format: format.combine(format.timestamp(), format.colorize(), this.format),
          handleExceptions: true,
        })
      );
    }
    if (file.active) {
      const folder = dirname(join(resolve(process.env.appRoot as string), file.path));
      if (!existsSync(folder)) mkdirSync(folder, { recursive: true });

      logTransports.push(
        new transports.File({
          level: file.level,
          filename: folder,
          format: format.combine(format.timestamp(), format.colorize(), this.format),
          handleExceptions: true,
          maxsize: 5242880,
          maxFiles: 5,
        })
      );
    }
    return logTransports;
  };

  private init = () =>
  (this.logger = createLogger({
    transports: this.createLogTransports(),
    exitOnError: false,
  }));

  log = (message: any) => this.logger.log("debug", message);

  info = (message: any) => this.logger.info(message);

  warn = (message: any) => this.logger.warn(message);

  error = (message: any) => this.logger.error(message);
}
