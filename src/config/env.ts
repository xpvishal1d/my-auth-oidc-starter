import "dotenv/config";
import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().default(3000),
  DATABASE_URL: z.string().min(1),
  BASE_URL: z.string().url(),
  ISSUER: z.string().url(),
  SESSION_COOKIE_NAME: z.string().default("sid"),
  SESSION_TTL_DAYS: z.coerce.number().default(30),
  ADMIN_API_KEY: z.string().min(1),
  JWT_PRIVATE_KEY_PATH: z.string().min(1),
  JWT_PUBLIC_KEY_PATH: z.string().min(1),
  JWT_KEY_ID: z.string().min(1)
});

export const env = envSchema.parse(process.env);
