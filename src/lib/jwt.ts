import { readFile } from "node:fs/promises";
import { exportJWK, importPKCS8, importSPKI, jwtVerify, SignJWT } from "jose";
import { env } from "../config/env.js";
import { randomToken } from "./crypto.js";

type LoadedKeys = {
  privateKey: Awaited<ReturnType<typeof importPKCS8>>;
  publicKey: Awaited<ReturnType<typeof importSPKI>>;
  jwk: Record<string, unknown>;
};

let keyCache: Promise<LoadedKeys> | null = null;

async function loadKeys(): Promise<LoadedKeys> {
  if (!keyCache) {
    keyCache = (async () => {
      const [privatePem, publicPem] = await Promise.all([
        readFile(env.JWT_PRIVATE_KEY_PATH, "utf8"),
        readFile(env.JWT_PUBLIC_KEY_PATH, "utf8")
      ]);

      const privateKey = await importPKCS8(privatePem, "RS256");
      const publicKey = await importSPKI(publicPem, "RS256");
      const jwk = await exportJWK(publicKey);

      return {
        privateKey,
        publicKey,
        jwk: {
          ...jwk,
          kid: env.JWT_KEY_ID,
          alg: "RS256",
          use: "sig"
        }
      };
    })();
  }

  return keyCache;
}

export async function getJwks() {
  const { jwk } = await loadKeys();
  return { keys: [jwk] };
}

export async function signIdToken(params: {
  subject: string;
  audience: string;
  nonce?: string | null;
  email?: string;
  emailVerified?: boolean;
  name?: string;
  preferredUsername?: string;
}) {
  const { privateKey } = await loadKeys();

  const payload: Record<string, unknown> = {};
  if (params.email) payload.email = params.email;
  if (typeof params.emailVerified === "boolean") payload.email_verified = params.emailVerified;
  if (params.name) payload.name = params.name;
  if (params.preferredUsername) payload.preferred_username = params.preferredUsername;
  if (params.nonce) payload.nonce = params.nonce;

  return new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", kid: env.JWT_KEY_ID, typ: "JWT" })
    .setIssuer(env.ISSUER)
    .setSubject(params.subject)
    .setAudience(params.audience)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
}

export async function signAccessToken(params: {
  subject: string;
  clientId: string;
  scope: string;
}) {
  const { privateKey } = await loadKeys();
  const audience = `${env.ISSUER}/userinfo`;

  return new SignJWT({
    scope: params.scope,
    client_id: params.clientId,
    token_use: "access",
    jti: randomToken(16)
  })
    .setProtectedHeader({ alg: "RS256", kid: env.JWT_KEY_ID, typ: "at+jwt" })
    .setIssuer(env.ISSUER)
    .setSubject(params.subject)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime("15m")
    .sign(privateKey);
}

export async function verifyAccessToken(token: string) {
  const { publicKey } = await loadKeys();
  return jwtVerify(token, publicKey, {
    issuer: env.ISSUER,
    audience: `${env.ISSUER}/userinfo`
  });
}
