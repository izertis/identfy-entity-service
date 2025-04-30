import crypto from "crypto";

export function generateRandomHash() {
  return crypto.createHash("sha256").update(Math.random().toString()).digest("hex");
}

export function generateSha256HashFromString(input: string) {
  return crypto.createHash('sha256').update(input).digest('hex');
}
