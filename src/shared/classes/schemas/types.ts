import { SchemaObject } from "ajv";

export type SchemasTypes = "FullJsonSchemaValidator2021"

export interface Schema {
  schemaType: SchemasTypes;
  content: SchemaObject
}
