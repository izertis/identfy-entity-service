import { SchemaObject } from "ajv";
import { Schema } from "./types.js";
import {ajv} from '../../../shared/utils/schemas/validator.utils.js';

abstract class SchemaValidator {
  abstract validate(
    data: Record<string, any>,
  ): Promise<boolean>;
}

export class SchemaValidatorFactory {
  static generateValidator(schema: Schema): SchemaValidator {
    switch (schema.schemaType) {
      case 'FullJsonSchemaValidator2021':
        return new JsonSchemaValidator(schema.content);
      default:
        throw new Error('Unssuported Schema Type');
    }
  }
}

class JsonSchemaValidator extends SchemaValidator {
  validateFunction?: any = undefined;
  constructor(private schema: SchemaObject) {
    super();
  }

  // TODO: Consider the inclusion of a cache module
  async validate(data: Record<string, any>): Promise<boolean> {
    if (!this.validateFunction) {
      this.validateFunction = await ajv.compileAsync(this.schema);
    }
    const validationResult = this.validateFunction(data);
    return validationResult;
  }
}
