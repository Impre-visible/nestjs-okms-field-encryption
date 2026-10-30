import "reflect-metadata";
import { randomBytes } from "node:crypto";
import { CryptoService } from "../src/crypto/crypto.service";

/** Faux OKMS : une clé "emballée" est la clé en base64 préfixée par "wrapped:". */
export const fakeOkms = {
  unwrapDataKey: async (w: string) => Buffer.from(w.replace("wrapped:", ""), "base64"),
} as any;

export const wrap = (k: Buffer) => `wrapped:${k.toString("base64")}`;

export const keys = { k1: randomBytes(32), k2: randomBytes(32), idx: randomBytes(32) };

export async function makeCrypto(fieldKeys: string, current: string) {
  process.env.FIELD_KEYS = fieldKeys;
  process.env.FIELD_KEY_CURRENT = current;
  process.env.BLIND_INDEX_KEY = wrap(keys.idx);
  const s = new CryptoService(fakeOkms);
  await s.onModuleInit();
  return s;
}

export const k1Only = () => makeCrypto(`k1:${wrap(keys.k1)}`, "k1");
export const k1k2 = () => makeCrypto(`k1:${wrap(keys.k1)},k2:${wrap(keys.k2)}`, "k2");
