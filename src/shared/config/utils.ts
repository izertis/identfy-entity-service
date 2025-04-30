import nconf from "nconf";

export function getOptionalString(key: string, defaultValue?: string ): string | undefined {
  return nconf.get(key) ? String(nconf.get(key)) : defaultValue;
}

export function getString(key: string, defaultValue?: string): string {
  const value = getOptionalString(key, defaultValue);
  if (!value) {
    throw new Error(`Setting '${key}' not defined`);
  }
  return value;
}

export function getOptionalNumber(key: string, defaultValue?: number ): number | undefined {
  return nconf.get(key) ? Number(nconf.get(key)) : defaultValue;
}

export function getNumber(key: string, defaultValue?: number ): number {
  const value = getOptionalNumber(key, defaultValue);
  if (!value) {
    throw new Error(`Setting '${key}' not defined`);
  }
  return value;
}
