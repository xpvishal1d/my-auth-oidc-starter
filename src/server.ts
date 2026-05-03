import express from "express";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { and, eq, gt, isNull } from "drizzle-orm";
import { z } from "zod";
import { env } from "./config/env.js";
import { db } from "./db/index.js";
import {
  authCodes,
  oauthClients,
  refreshTokens,
  sessions,
  tokenRevocations,
  users
} from "./db/schema.js";
import {
  hashPassword,
  hashSecret,
  isValidCodeVerifier,
  isValidPkceChallenge,
  randomToken,
  sha256,
  verifyPassword,
  verifySecret
} from "./lib/crypto.js";
import {
  getJwks,
  signAccessToken,
  signIdToken,
  verifyAccessToken
} from "./lib/jwt.js";
import { loginPage, signupPage } from "./views.js";

const app = express();
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());

const isProd = env.NODE_ENV === "production";
const ACCESS_TOKEN_AUDIENCE = `${env.ISSUER}/userinfo`;

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "too_many_requests" }
});

const tokenLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "too_many_requests" }
});

function cookieOptions(maxAgeMs: number) {
  return {
    httpOnly: true,
    sameSite: "lax" as const,
    secure: isProd,
    path: "/",
    maxAge: maxAgeMs
  };
}

function oauthError(
  res: express.Response,
  status: number,
  error: string,
  description?: string
) {
  return res.status(status).json({
    error,
    ...(description ? { error_description: description } : {})
  });
}

function redirectWithOAuthError(redirectUri: string, state: string | undefined, error: string, description?: string) {
  const url = new URL(redirectUri);
  url.searchParams.set("error", error);
  if (description) url.searchParams.set("error_description", description);
  if (state) url.searchParams.set("state", state);
  return url.toString();
}

async function createSession(userId: string) {
  const sessionId = randomToken(32);
  const expiresAt = new Date(Date.now() + env.SESSION_TTL_DAYS * 24 * 60 * 60 * 1000);

  await db.insert(sessions).values({
    id: sessionId,
    userId,
    expiresAt
  });

  return { sessionId, expiresAt };
}

async function getCurrentUser(req: express.Request) {
  const sid = req.cookies[env.SESSION_COOKIE_NAME];
  if (!sid) return null;

  const sessionRows = await db
    .select()
    .from(sessions)
    .where(
      and(
        eq(sessions.id, sid),
        isNull(sessions.revokedAt),
        gt(sessions.expiresAt, new Date())
      )
    )
    .limit(1);

  const session = sessionRows[0];
  if (!session) return null;

  const userRows = await db
    .select()
    .from(users)
    .where(eq(users.id, session.userId))
    .limit(1);

  return userRows[0] ?? null;
}

async function loadClient(clientId: string) {
  const rows = await db.select().from(oauthClients).where(eq(oauthClients.id, clientId)).limit(1);
  return rows[0] ?? null;
}

async function verifyClientAuth(req: express.Request, body: {
  client_id?: string;
  client_secret?: string;
}) {
  const auth = req.header("authorization");
  let clientId: string | undefined = body.client_id;
  let clientSecret: string | undefined = body.client_secret;

  if (auth?.startsWith("Basic ")) {
    const raw = Buffer.from(auth.slice("Basic ".length), "base64").toString("utf8");
    const idx = raw.indexOf(":");
    if (idx >= 0) {
      clientId = raw.slice(0, idx);
      clientSecret = raw.slice(idx + 1);
    }
  }

  if (!clientId) {
    return { client: null, error: "invalid_client", status: 401 as const };
  }

  const client = await loadClient(clientId);
  if (!client) {
    return { client: null, error: "invalid_client", status: 401 as const };
  }

  if (!client.isPublic) {
    if (!client.secretHash || !clientSecret) {
      return { client: null, error: "invalid_client", status: 401 as const };
    }
    const ok = await verifySecret(clientSecret, client.secretHash);
    if (!ok) {
      return { client: null, error: "invalid_client", status: 401 as const };
    }
  }

  return { client, error: null, status: 200 as const };
}

function parseScope(scope: string) {
  return Array.from(new Set(scope.split(/\s+/).filter(Boolean)));
}

function hasScope(scopeString: string, scope: string) {
  return parseScope(scopeString).includes(scope);
}

async function issueRefreshToken(params: {
  userId: string;
  clientId: string;
  scope: string;
  familyId?: string;
  previousTokenId?: string;
}) {
  const refreshToken = randomToken(48);
  const familyId = params.familyId ?? crypto.randomUUID();
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

  const inserted = await db
    .insert(refreshTokens)
    .values({
      tokenHash: sha256(refreshToken),
      familyId,
      userId: params.userId,
      clientId: params.clientId,
      scope: params.scope,
      expiresAt,
      replacedByTokenId: params.previousTokenId ?? null
    })
    .returning();

  return {
    refreshToken,
    row: inserted[0]
  };
}

async function revokeAccessTokenJti(jti: string, expiresAt: Date) {
  await db.insert(tokenRevocations).values({
    tokenId: jti,
    tokenType: "access_token",
    expiresAt
  }).onConflictDoNothing();
}

async function isAccessTokenRevoked(jti: string) {
  const rows = await db.select().from(tokenRevocations).where(eq(tokenRevocations.tokenId, jti)).limit(1);
  const row = rows[0];
  return Boolean(row && row.expiresAt > new Date());
}

function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
  const key = req.header("x-admin-key");
  if (!key || key !== env.ADMIN_API_KEY) {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
}

app.get("/", (_req, res) => {
  res.json({
    service: "my-auth",
    issuer: env.ISSUER
  });
});

app.get("/.well-known/openid-configuration", (_req, res) => {
  res.json({
    issuer: env.ISSUER,
    authorization_endpoint: `${env.BASE_URL}/authorize`,
    token_endpoint: `${env.BASE_URL}/token`,
    userinfo_endpoint: `${env.BASE_URL}/userinfo`,
    jwks_uri: `${env.BASE_URL}/jwks.json`,
    registration_endpoint: `${env.BASE_URL}/admin/clients`,
    revocation_endpoint: `${env.BASE_URL}/revoke`,
    introspection_endpoint: `${env.BASE_URL}/introspect`,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    subject_types_supported: ["public"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    id_token_signing_alg_values_supported: ["RS256"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
    scopes_supported: ["openid", "profile", "email", "offline_access"],
    claims_supported: [
      "sub",
      "iss",
      "aud",
      "exp",
      "iat",
      "nonce",
      "email",
      "email_verified",
      "name",
      "preferred_username"
    ],
    code_challenge_methods_supported: ["S256"]
  });
});

app.get("/jwks.json", async (_req, res) => {
  res.json(await getJwks());
});

app.get("/signup", (req, res) => {
  const returnTo = typeof req.query.returnTo === "string" ? req.query.returnTo : "/";
  res.type("html").send(signupPage({ returnTo }));
});

app.post("/signup", authLimiter, async (req, res) => {
  const schema = z.object({
    name: z.string().min(1).max(200),
    email: z.string().email().max(320),
    password: z.string().min(8).max(200),
    returnTo: z.string().optional()
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).type("html").send(signupPage({ returnTo: "/", error: "Invalid signup data" }));
  }

  const { name, email, password, returnTo = "/" } = parsed.data;
  const normalizedEmail = email.toLowerCase();

  const existing = await db.select().from(users).where(eq(users.email, normalizedEmail)).limit(1);
  if (existing[0]) {
    return res.status(400).type("html").send(signupPage({ returnTo, error: "Email already exists" }));
  }

  const inserted = await db.insert(users).values({
    name,
    email: normalizedEmail,
    emailVerified: false,
    passwordHash: await hashPassword(password)
  }).returning();

  const user = inserted[0];
  const { sessionId, expiresAt } = await createSession(user.id);

  res.cookie(env.SESSION_COOKIE_NAME, sessionId, cookieOptions(expiresAt.getTime() - Date.now()));
  return res.redirect(returnTo);
});

app.get("/login", (req, res) => {
  const returnTo = typeof req.query.returnTo === "string" ? req.query.returnTo : "/";
  res.type("html").send(loginPage({ returnTo }));
});

app.post("/login", authLimiter, async (req, res) => {
  const schema = z.object({
    email: z.string().email().max(320),
    password: z.string().min(1).max(200),
    returnTo: z.string().optional()
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).type("html").send(loginPage({ returnTo: "/", error: "Invalid login data" }));
  }

  const { email, password, returnTo = "/" } = parsed.data;
  const normalizedEmail = email.toLowerCase();

  const rows = await db.select().from(users).where(eq(users.email, normalizedEmail)).limit(1);
  const user = rows[0];
  if (!user) {
    return res.status(401).type("html").send(loginPage({ returnTo, error: "Invalid email or password" }));
  }

  const ok = await verifyPassword(password, user.passwordHash);
  if (!ok) {
    return res.status(401).type("html").send(loginPage({ returnTo, error: "Invalid email or password" }));
  }

  const { sessionId, expiresAt } = await createSession(user.id);
  res.cookie(env.SESSION_COOKIE_NAME, sessionId, cookieOptions(expiresAt.getTime() - Date.now()));
  return res.redirect(returnTo);
});

app.post("/logout", async (req, res) => {
  const sid = req.cookies[env.SESSION_COOKIE_NAME];
  if (sid) {
    await db.update(sessions).set({ revokedAt: new Date() }).where(eq(sessions.id, sid));
  }
  res.clearCookie(env.SESSION_COOKIE_NAME, { path: "/" });
  return res.json({ ok: true });
});

app.post("/admin/clients", requireAdmin, async (req, res) => {
  const schema = z.object({
    name: z.string().min(1).max(200),
    redirectUris: z.array(z.string().url()).min(1),
    scopes: z.array(z.string().min(1)).default(["openid", "profile", "email", "offline_access"]),
    isPublic: z.boolean().default(false)
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid_body" });
  }

  const clientId = `client_${randomToken(16)}`;
  const clientSecret = parsed.data.isPublic ? null : randomToken(32);

  await db.insert(oauthClients).values({
    id: clientId,
    name: parsed.data.name,
    secretHash: clientSecret ? await hashSecret(clientSecret) : null,
    redirectUris: parsed.data.redirectUris,
    scopes: parsed.data.scopes,
    isPublic: parsed.data.isPublic,
    requirePkce: true
  });

  return res.status(201).json({
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uris: parsed.data.redirectUris,
    scopes: parsed.data.scopes,
    is_public: parsed.data.isPublic
  });
});

app.get("/authorize", async (req, res) => {
  const schema = z.object({
    response_type: z.literal("code"),
    client_id: z.string().min(1),
    redirect_uri: z.string().url(),
    scope: z.string().min(1),
    state: z.string().optional(),
    nonce: z.string().optional(),
    code_challenge: z.string().min(43).max(128),
    code_challenge_method: z.literal("S256")
  });

  const parsed = schema.safeParse(req.query);
  if (!parsed.success) {
    return oauthError(res, 400, "invalid_request", "Invalid authorize request");
  }

  const q = parsed.data;
  if (!hasScope(q.scope, "openid")) {
    return oauthError(res, 400, "invalid_scope", "openid scope is required");
  }

  const client = await loadClient(q.client_id);
  if (!client) {
    return oauthError(res, 400, "unauthorized_client", "Unknown client");
  }

  if (!(client.redirectUris as string[]).includes(q.redirect_uri)) {
    return oauthError(res, 400, "invalid_request", "redirect_uri is not registered for this client");
  }

  const requestedScopes = parseScope(q.scope);
  const allowedScopes = client.scopes as string[];
  for (const scope of requestedScopes) {
    if (!allowedScopes.includes(scope)) {
      return oauthError(res, 400, "invalid_scope", `Client does not allow scope: ${scope}`);
    }
  }

  if (client.requirePkce && (!isValidPkceChallenge(q.code_challenge) || q.code_challenge_method !== "S256")) {
    return oauthError(res, 400, "invalid_request", "PKCE with S256 is required");
  }

  const currentUser = await getCurrentUser(req);
  if (!currentUser) {
    const returnTo = `${req.path}?${new URLSearchParams(req.query as Record<string, string>).toString()}`;
    return res.redirect(`/login?returnTo=${encodeURIComponent(returnTo)}`);
  }

  const code = randomToken(32);
  const expiresAt = new Date(Date.now() + 60 * 1000);

  await db.insert(authCodes).values({
    codeHash: sha256(code),
    userId: currentUser.id,
    clientId: q.client_id,
    redirectUri: q.redirect_uri,
    scope: q.scope,
    nonce: q.nonce ?? null,
    codeChallenge: q.code_challenge,
    codeChallengeMethod: q.code_challenge_method,
    expiresAt
  });

  const redirectUrl = new URL(q.redirect_uri);
  redirectUrl.searchParams.set("code", code);
  if (q.state) redirectUrl.searchParams.set("state", q.state);

  return res.redirect(redirectUrl.toString());
});

app.post("/token", tokenLimiter, async (req, res) => {
  const clientAuthSchema = z.object({
    grant_type: z.enum(["authorization_code", "refresh_token"]),
    code: z.string().optional(),
    redirect_uri: z.string().url().optional(),
    refresh_token: z.string().optional(),
    code_verifier: z.string().optional(),
    client_id: z.string().optional(),
    client_secret: z.string().optional()
  });

  const parsed = clientAuthSchema.safeParse(req.body);
  if (!parsed.success) {
    return oauthError(res, 400, "invalid_request", "Invalid token request");
  }

  const { client, error, status } = await verifyClientAuth(req, {
    client_id: parsed.data.client_id,
    client_secret: parsed.data.client_secret
  });

  if (!client) {
    return oauthError(res, status, error ?? "invalid_client");
  }

  if (parsed.data.grant_type === "authorization_code") {
    if (!parsed.data.code || !parsed.data.redirect_uri || !parsed.data.code_verifier) {
      return oauthError(res, 400, "invalid_request", "Missing code, redirect_uri, or code_verifier");
    }

    if (!isValidCodeVerifier(parsed.data.code_verifier)) {
      return oauthError(res, 400, "invalid_request", "Invalid code_verifier");
    }

    const codeHash = sha256(parsed.data.code);
    const codeRows = await db.select().from(authCodes).where(eq(authCodes.codeHash, codeHash)).limit(1);
    const codeRow = codeRows[0];
    if (!codeRow) {
      return oauthError(res, 400, "invalid_grant", "Invalid authorization code");
    }

    if (codeRow.usedAt) {
      return oauthError(res, 400, "invalid_grant", "Authorization code already used");
    }

    if (codeRow.expiresAt <= new Date()) {
      return oauthError(res, 400, "invalid_grant", "Authorization code expired");
    }

    if (codeRow.clientId !== client.id || codeRow.redirectUri !== parsed.data.redirect_uri) {
      return oauthError(res, 400, "invalid_grant", "Client or redirect_uri mismatch");
    }

    if (sha256(parsed.data.code_verifier) !== codeRow.codeChallenge) {
      return oauthError(res, 400, "invalid_grant", "PKCE verification failed");
    }

    await db.update(authCodes).set({ usedAt: new Date() }).where(eq(authCodes.id, codeRow.id));

    const userRows = await db.select().from(users).where(eq(users.id, codeRow.userId)).limit(1);
    const user = userRows[0];
    if (!user) {
      return oauthError(res, 400, "invalid_grant", "User not found");
    }

    const idToken = await signIdToken({
      subject: user.id,
      audience: client.id,
      nonce: codeRow.nonce,
      email: user.email,
      emailVerified: user.emailVerified,
      name: user.name,
      preferredUsername: user.email.split("@")[0]
    });

    const accessToken = await signAccessToken({
      subject: user.id,
      clientId: client.id,
      scope: codeRow.scope
    });

    let refreshToken: string | undefined;
    if (hasScope(codeRow.scope, "offline_access")) {
      const issued = await issueRefreshToken({
        userId: user.id,
        clientId: client.id,
        scope: codeRow.scope
      });
      refreshToken = issued.refreshToken;
    }

    return res.json({
      access_token: accessToken,
      id_token: idToken,
      ...(refreshToken ? { refresh_token: refreshToken } : {}),
      token_type: "Bearer",
      expires_in: 900,
      scope: codeRow.scope
    });
  }

  if (!parsed.data.refresh_token) {
    return oauthError(res, 400, "invalid_request", "Missing refresh_token");
  }

  const tokenHash = sha256(parsed.data.refresh_token);
  const rows = await db.select().from(refreshTokens).where(eq(refreshTokens.tokenHash, tokenHash)).limit(1);
  const refreshRow = rows[0];

  if (!refreshRow || refreshRow.revokedAt || refreshRow.expiresAt <= new Date()) {
    return oauthError(res, 400, "invalid_grant", "Invalid refresh token");
  }

  if (refreshRow.clientId !== client.id) {
    return oauthError(res, 400, "invalid_grant", "Client mismatch");
  }

  await db.update(refreshTokens).set({ revokedAt: new Date() }).where(eq(refreshTokens.id, refreshRow.id));

  const rotated = await issueRefreshToken({
    userId: refreshRow.userId,
    clientId: refreshRow.clientId,
    scope: refreshRow.scope,
    familyId: refreshRow.familyId,
    previousTokenId: refreshRow.id
  });

  const accessToken = await signAccessToken({
    subject: refreshRow.userId,
    clientId: refreshRow.clientId,
    scope: refreshRow.scope
  });

  return res.json({
    access_token: accessToken,
    refresh_token: rotated.refreshToken,
    token_type: "Bearer",
    expires_in: 900,
    scope: refreshRow.scope
  });
});

app.get("/userinfo", async (req, res) => {
  const auth = req.header("authorization");
  if (!auth?.startsWith("Bearer ")) {
    return oauthError(res, 401, "invalid_token", "Missing bearer token");
  }

  try {
    const token = auth.slice("Bearer ".length);
    const verified = await verifyAccessToken(token);
    const payload = verified.payload;

    const jti = payload.jti;
    if (typeof jti === "string" && await isAccessTokenRevoked(jti)) {
      return oauthError(res, 401, "invalid_token", "Token revoked");
    }

    const userId = payload.sub;
    if (!userId) {
      return oauthError(res, 401, "invalid_token", "Missing subject");
    }

    const rows = await db.select().from(users).where(eq(users.id, userId)).limit(1);
    const user = rows[0];
    if (!user) {
      return oauthError(res, 404, "invalid_token", "User not found");
    }

    const scope = typeof payload.scope === "string" ? payload.scope : "";
    const response: Record<string, unknown> = {
      sub: user.id
    };

    if (hasScope(scope, "profile")) {
      response.name = user.name;
      response.preferred_username = user.email.split("@")[0];
    }
    if (hasScope(scope, "email")) {
      response.email = user.email;
      response.email_verified = user.emailVerified;
    }

    return res.json(response);
  } catch {
    return oauthError(res, 401, "invalid_token", "Invalid access token");
  }
});

app.post("/revoke", async (req, res) => {
  const schema = z.object({
    token: z.string().min(1),
    token_type_hint: z.enum(["access_token", "refresh_token"]).optional(),
    client_id: z.string().optional(),
    client_secret: z.string().optional()
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return oauthError(res, 400, "invalid_request", "Invalid revocation request");
  }

  const { client, error, status } = await verifyClientAuth(req, {
    client_id: parsed.data.client_id,
    client_secret: parsed.data.client_secret
  });

  if (!client) {
    return oauthError(res, status, error ?? "invalid_client");
  }

  const { token, token_type_hint } = parsed.data;

  if (token_type_hint === "refresh_token") {
    await db.update(refreshTokens).set({ revokedAt: new Date() }).where(eq(refreshTokens.tokenHash, sha256(token)));
    return res.json({ revoked: true });
  }

  if (token_type_hint === "access_token") {
    try {
      const verified = await verifyAccessToken(token);
      const jti = verified.payload.jti;
      const exp = verified.payload.exp;
      if (typeof jti === "string" && typeof exp === "number") {
        await revokeAccessTokenJti(jti, new Date(exp * 1000));
      }
    } catch {
      // RFC 7009 says the response should be successful even if the token is invalid.
    }
    return res.json({ revoked: true });
  }

  // fallback: try both
  await db.update(refreshTokens).set({ revokedAt: new Date() }).where(eq(refreshTokens.tokenHash, sha256(token)));
  try {
    const verified = await verifyAccessToken(token);
    const jti = verified.payload.jti;
    const exp = verified.payload.exp;
    if (typeof jti === "string" && typeof exp === "number") {
      await revokeAccessTokenJti(jti, new Date(exp * 1000));
    }
  } catch {
    // ignore
  }

  return res.json({ revoked: true });
});

app.post("/introspect", async (req, res) => {
  const schema = z.object({
    token: z.string().min(1),
    token_type_hint: z.enum(["access_token", "refresh_token"]).optional(),
    client_id: z.string().optional(),
    client_secret: z.string().optional()
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return oauthError(res, 400, "invalid_request", "Invalid introspection request");
  }

  const { client, error, status } = await verifyClientAuth(req, {
    client_id: parsed.data.client_id,
    client_secret: parsed.data.client_secret
  });

  if (!client) {
    return oauthError(res, status, error ?? "invalid_client");
  }

  const token = parsed.data.token;
  const hint = parsed.data.token_type_hint;

  if (hint === "refresh_token" || (!hint && token.length > 1000 === false)) {
    const rows = await db.select().from(refreshTokens).where(eq(refreshTokens.tokenHash, sha256(token))).limit(1);
    const row = rows[0];
    const active = Boolean(row && !row.revokedAt && row.expiresAt > new Date() && row.clientId === client.id);
    return res.json({
      active,
      ...(active && row ? {
        scope: row.scope,
        client_id: row.clientId,
        sub: row.userId,
        exp: Math.floor(row.expiresAt.getTime() / 1000),
        token_type: "refresh_token"
      } : {})
    });
  }

  try {
    const verified = await verifyAccessToken(token);
    const payload = verified.payload;
    const jti = payload.jti;
    const exp = payload.exp;
    const revoked = typeof jti === "string" ? await isAccessTokenRevoked(jti) : true;

    const active = Boolean(!revoked && payload.sub && typeof exp === "number" && exp * 1000 > Date.now());
    return res.json({
      active,
      ...(active ? {
        sub: payload.sub,
        client_id: typeof payload.client_id === "string" ? payload.client_id : undefined,
        scope: typeof payload.scope === "string" ? payload.scope : undefined,
        exp: exp,
        token_type: "access_token"
      } : {})
    });
  } catch {
    return res.json({ active: false });
  }
});

app.get("/me", async (req, res) => {
  const user = await getCurrentUser(req);
  return res.json({
    authenticated: Boolean(user),
    user: user ? {
      id: user.id,
      email: user.email,
      emailVerified: user.emailVerified,
      name: user.name
    } : null
  });
});

app.listen(env.PORT, () => {
  console.log(`my-auth listening on ${env.BASE_URL}`);
});
