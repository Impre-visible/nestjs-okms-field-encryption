import assert from "node:assert/strict";
import { test } from "node:test";
import { k1k2, k1Only, keys, makeCrypto, wrap } from "./helpers";

test("aller-retour", async () => {
  const s = await k1Only();
  const c = s.encrypt("FR76 3000 6000 0112 3456 7890 189", "Client.iban.42");
  assert.match(c, /^v1\.k1\./);
  assert.equal(s.decrypt(c, "Client.iban.42"), "FR76 3000 6000 0112 3456 7890 189");
});

test("chiffrement non déterministe", async () => {
  const s = await k1Only();
  assert.notEqual(s.encrypt("x", "a"), s.encrypt("x", "a"));
});

test("chiffré déplacé vers une autre ligne ou colonne : refusé", async () => {
  const s = await k1Only();
  const c = s.encrypt("secret", "Client.iban.1");
  assert.throws(() => s.decrypt(c, "Client.iban.2"));
  assert.throws(() => s.decrypt(c, "Client.notes.1"));
});

test("chiffré modifié : refusé", async () => {
  const s = await k1Only();
  const parts = s.encrypt("secret", "a").split(".");
  const ct = Buffer.from(parts[3], "base64url");
  ct[0] ^= 1;
  parts[3] = ct.toString("base64url");
  assert.throws(() => s.decrypt(parts.join("."), "a"));
});

test("rotation : ancien chiffré lisible, nouveau sur k2", async () => {
  const old = (await k1Only()).encrypt("secret", "a");
  const s = await k1k2();
  assert.equal(s.decrypt(old, "a"), "secret");
  assert.ok(s.needsRotation(old));
  assert.ok(!s.needsRotation(s.encrypt("secret", "a")));
});

test("clé retirée : refus explicite", async () => {
  const old = (await k1Only()).encrypt("secret", "a");
  const s = await makeCrypto(`k2:${wrap(keys.k2)}`, "k2");
  assert.throws(() => s.decrypt(old, "a"), /k1 inconnue/);
});

test("index aveugle : stable, normalisé, cloisonné par colonne", async () => {
  const s = await k1Only();
  assert.equal(s.blindIndex("123 456 789 00012", "Client.siret"), s.blindIndex("12345678900012", "Client.siret"));
  assert.notEqual(s.blindIndex("12345678900012", "Client.siret"), s.blindIndex("12345678900012", "Other.siret"));
});
