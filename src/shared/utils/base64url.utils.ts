export function toBase64Url(input: string): string {
  const utf8Buffer = Buffer.from(input, 'utf-8');
  return utf8Buffer.toString('base64url');
}
