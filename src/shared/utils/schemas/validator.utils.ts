import Ajv2020, {AnySchemaObject} from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import fetch from 'node-fetch';

async function loadSchema(uri: string): Promise<AnySchemaObject> {
  const response = await fetch(uri);
  if (!response.ok) {
    throw new Error(`
      An error was received when fetchin remote schema: ${response.statusText}`);
  }
  return (await response.json()) as AnySchemaObject;
}

export const ajv = new (Ajv2020 as any)({loadSchema: loadSchema});
(addFormats as any)(ajv);
