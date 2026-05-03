import { mkdirSync, writeFileSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: "spki",
    format: "pem"
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem"
  }
});

mkdirSync("keys", { recursive: true });
writeFileSync("keys/private.pem", privateKey);
writeFileSync("keys/public.pem", publicKey);

console.log("Generated keys/private.pem and keys/public.pem");
