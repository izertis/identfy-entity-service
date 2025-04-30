import {SchemaObject} from 'ajv';
import {Result} from '../utility/result.js';
import { Schema, SchemasTypes } from './types.js';

abstract class SchemaGetter {
  constructor(protected schemaType: SchemasTypes) {}
  abstract getSchema(uri: string): Promise<Result<Schema, Error>>;
}

class RemoteJsonSchemaGetter extends SchemaGetter {
  async getSchema(uri: string): Promise<Result<Schema, Error>> {
    try {
      const response = await fetch(uri);
      return Result.Ok(
        {
          schemaType: this.schemaType,
          content: await response.json() as SchemaObject
        }
      );
    } catch (e: any) {
      return Result.Err(new Error(`Can't recover credential schema: ${e}`));
    }
  }
}

export class SchemaGetterFactory {
  // For now, we only support JsonSchema
  static generateGetter(schemaType: string): SchemaGetter {
    switch (schemaType) {
      case 'FullJsonSchemaValidator2021':
        return new RemoteJsonSchemaGetter(schemaType);
      default:
        throw new Error('Unssuported Schema Type');
    }
  }
}
