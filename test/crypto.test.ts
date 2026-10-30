import "reflect-metadata";
import { randomBytes } from "node:crypto";
import assert from "node:assert/strict";
import { test } from "node:test";
import { CryptoService } from "../src/crypto/crypto.service";
import { ClientsRepository } from "../src/clients/clients.repository";

// Faux OKMS : "emballer" = préfixer la clé en base64 avec "wrapped:"
const fakeOkms = {
  unwrapDataKey: async (w: string) => Buffer.from(w.replace("wrapped:", ""), "base64"),
} as any;
const wrap = (k: Buffer) => `wrapped:${k.toString("base64")}`;

const k1 = randomBytes(32), k2 = randomBytes(32), idx = randomBytes(32);

async function service(keys: string, current: string) {
  process.env.FIELD_KEYS = keys;
  process.env.FIELD_KEY_CURRENT = current;
  process.env.BLIND_INDEX_KEY = wrap(idx);
  const s = new CryptoService(fakeOkms);
  await s.onModuleInit();
  return s;
}

test("aller-retour", async () => {
  const s = await service(`k1:${wrap(k1)}`, "k1");
  const c = s.encrypt("FR76 3000 6000 0112 3456 7890 189", "Client.iban.42");
  assert.match(c, /^v1\.k1\./);
  assert.equal(s.decrypt(c, "Client.iban.42"), "FR76 3000 6000 0112 3456 7890 189");
});

test("chiffrement non déterministe", async () => {
  const s = await service(`k1:${wrap(k1)}`, "k1");
  assert.notEqual(s.encrypt("x", "a"), s.encrypt("x", "a"));
});

test("chiffré déplacé vers une autre ligne : refusé", async () => {
  const s = await service(`k1:${wrap(k1)}`, "k1");
  const c = s.encrypt("secret", "Client.iban.1");
  assert.throws(() => s.decrypt(c, "Client.iban.2"));
  assert.throws(() => s.decrypt(c, "Client.notes.1"));
});

test("chiffré modifié : refusé", async () => {
  const s = await service(`k1:${wrap(k1)}`, "k1");
  const parts = s.encrypt("secret", "a").split(".");
  const ct = Buffer.from(parts[3], "base64url");
  ct[0] ^= 1;
  parts[3] = ct.toString("base64url");
  assert.throws(() => s.decrypt(parts.join("."), "a"));
});

test("rotation : ancien chiffré lisible, nouveau sur k2", async () => {
  const old = (await service(`k1:${wrap(k1)}`, "k1")).encrypt("secret", "a");
  const s = await service(`k1:${wrap(k1)},k2:${wrap(k2)}`, "k2");
  assert.equal(s.decrypt(old, "a"), "secret");
  assert.ok(s.needsRotation(old));
  assert.ok(!s.needsRotation(s.encrypt("secret", "a")));
});

test("clé retirée : refus explicite", async () => {
  const old = (await service(`k1:${wrap(k1)}`, "k1")).encrypt("secret", "a");
  const s = await service(`k2:${wrap(k2)}`, "k2");
  assert.throws(() => s.decrypt(old, "a"), /k1 inconnue/);
});

test("index aveugle : stable, normalisé, cloisonné par colonne", async () => {
  const s = await service(`k1:${wrap(k1)}`, "k1");
  assert.equal(s.blindIndex("123 456 789 00012", "Client.siret"), s.blindIndex("12345678900012", "Client.siret"));
  assert.notEqual(s.blindIndex("12345678900012", "Client.siret"), s.blindIndex("12345678900012", "Other.siret"));
});

test("repository : rien en clair en base, recherche et rotation", async () => {
  const table = new Map<string, any>();
  const prisma = {
    client: {
      create: async ({ data }: any) => (table.set(data.id, { ...data }), { ...data }),
      update: async ({ where, data }: any) => (table.set(where.id, { ...data }), { ...data }),
      findUnique: async ({ where }: any) =>
        where.id ? table.get(where.id) ?? null : [...table.values()].find((r) => r.siretIdx === where.siretIdx) ?? null,
      findMany: async ({ cursor, take }: any) => {
        const rows = [...table.values()].sort((a, b) => a.id.localeCompare(b.id));
        const start = cursor ? rows.findIndex((r) => r.id === cursor.id) + 1 : 0;
        return rows.slice(start, start + take);
      },
    },
  } as any;

  let repo = new ClientsRepository(prisma, await service(`k1:${wrap(k1)}`, "k1"));
  const created = await repo.create({ name: "ACME", siret: "12345678900012", iban: "FR76...", notes: null });

  const raw = JSON.stringify([...table.values()]);
  assert.ok(!raw.includes("12345678900012") && !raw.includes("FR76"), "donnée en clair en base");

  assert.equal((await repo.findBySiret("123 456 789 00012"))?.id, created.id);

  repo = new ClientsRepository(prisma, await service(`k1:${wrap(k1)},k2:${wrap(k2)}`, "k2"));
  assert.equal(await repo.rotateKeys(1), 1);
  assert.match(table.get(created.id).siret, /^v1\.k2\./);
  assert.equal((await repo.findById(created.id))?.iban, "FR76...");
});
