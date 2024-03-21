import { singleton } from "tsyringe";
import { readFileSync } from "fs";
import { join, resolve } from "path";
import Logger from "../../shared/classes/logger.js";
import { LANGUAGE } from "../../shared/config/configuration.js";

@singleton()
export default class Translator {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private dictionary: any = {};

  constructor(private logger: Logger) {
    this.init();
  }

  private init = () => {
    const { allowed, location } = LANGUAGE;
    allowed.forEach((locale) => {
      const path = resolve(join(process.env.appRoot as string, location));
      const file = readFileSync(`${path}/${locale}.json`, "utf-8");
      this.dictionary[locale] = JSON.parse(file);
    });
  };

  translate = (key: string, language: string): string => {
    const dictionary = this.dictionary[language];

    if (!dictionary) {
      this.logger.warn(`Dictionary for '${language}' does not exists`);
      return key;
    }
    const value = key?.split(".").reduce((v, k) => v?.[k], dictionary);
    return value || key;
  };
}
