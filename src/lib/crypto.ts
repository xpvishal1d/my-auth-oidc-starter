import bcrypt from "bcryptjs";
import { createHash, randomBytes } from "node:crypto";

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function sha256(input: string): string {
  return createHash("sha256").update(input).digest("base64url");
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export async function hashSecret(secret: string): Promise<string> {
  return bcrypt.hash(secret, 12);
}

export async function verifySecret(secret: string, hash: string): Promise<boolean> {
  return bcrypt.compare(secret, hash);
}

export function isValidCodeVerifier(codeVerifier: string): boolean {
  return /^[A-Za-z0-9-._~]{43,128}$/.test(codeVerifier);
}

export function isValidPkceChallenge(codeChallenge: string): boolean {
  return /^[A-Za-z0-9-._~]{43,128}$/.test(codeChallenge);
}
