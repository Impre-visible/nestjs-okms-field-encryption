/**
 * Tests d'intégration de l'extension contre un vrai PostgreSQL.
 * Lancés par la CI (service postgres). En local :
 *   DATABASE_URL=postgresql://... npx prisma db push && npm test
 */
import assert from "node:assert/strict";
import { after, before, beforeEach, describe, test } from "node:test";
import { k1k2, k1Only } from "./helpers";

const DATABASE_URL = process.env.DATABASE_URL;

describe("extension Prisma de chiffrement", { skip: !DATABASE_URL && "DATABASE_URL absent" }, () => {
  let mod: typeof import("../src/prisma/prisma.module");
  let db: import("../src/prisma/prisma.module").PrismaDb;

  before(async () => {
    mod = await import("../src/prisma/prisma.module");
    db = mod.createPrismaClient(await k1Only(), DATABASE_URL);
  });

  beforeEach(async () => {
    await db.$executeRawUnsafe(`TRUNCATE "Invoice", "Client" CASCADE`);
  });

  after(async () => {
    await db?.$disconnect();
  });

  const acme = { name: "ACME", siret: "12345678900012", iban: "FR7630006000011234567890189", notes: "client VIP" };

  test("create : rien en clair en base, lecture déchiffrée", async () => {
    const c = await db.client.create({ data: acme });
    assert.equal(c.siret, acme.siret);
    assert.equal(c.iban, acme.iban);

    const raw = await db.$queryRawUnsafe<any[]>(`SELECT * FROM "Client"`);
    const dump = JSON.stringify(raw);
    for (const secret of [acme.siret, acme.iban, acme.notes]) assert.ok(!dump.includes(secret), `${secret} en clair`);
    assert.match(raw[0].siret, /^v1\.k1\./);
    assert.ok(raw[0].siretIdx);
  });

  test("valeurs null conservées", async () => {
    const c = await db.client.create({ data: { name: "Sans IBAN", siret: "1", iban: null } });
    assert.equal(c.iban, null);
    assert.equal(c.notes, null);
    assert.equal((await db.client.findFirst({ where: { iban: null } }))?.id, c.id);
  });

  test("recherche exacte via l'index aveugle (normalisée)", async () => {
    const c = await db.client.create({ data: acme });
    assert.equal((await db.client.findFirst({ where: { siret: "123 456 789 00012" } }))?.id, c.id);
    assert.equal((await db.client.findFirst({ where: { siret: { equals: acme.siret } } }))?.id, c.id);
    assert.equal((await db.client.findMany({ where: { siret: { in: ["x", acme.siret] } } })).length, 1);
    assert.equal(await db.client.findFirst({ where: { siret: "autre" } }), null);
    assert.equal((await db.client.findMany({ where: { OR: [{ siret: acme.siret }, { name: "x" }] } })).length, 1);
  });

  test("filtres impossibles sur un champ chiffré : refusés", async () => {
    await assert.rejects(db.client.findMany({ where: { siret: { contains: "123" } } }), /seuls l'égalité/);
    await assert.rejects(db.client.findMany({ where: { iban: "FR76" } }), /sans index/);
    await assert.rejects(db.client.findMany({ orderBy: { iban: "asc" } }), /trier/);
    await assert.rejects(db.invoice.findMany({ where: { client: { is: { iban: "x" } } } }), /relationnel/);
  });

  test("select sans id : l'id est ajouté pour pouvoir déchiffrer", async () => {
    await db.client.create({ data: acme });
    const [c] = await db.client.findMany({ select: { iban: true } });
    assert.equal(c.iban, acme.iban);
  });

  test("include : relation chiffrée déchiffrée", async () => {
    const c = await db.client.create({ data: acme });
    await db.invoice.create({ data: { clientId: c.id, amount: 100, label: "Mission audit" } });
    const withInvoices = await db.client.findUnique({ where: { id: c.id }, include: { invoices: true } });
    assert.equal(withInvoices?.invoices[0].label, "Mission audit");
    const inv = await db.invoice.findFirst({ include: { client: { select: { siret: true } } } });
    assert.equal(inv?.client.siret, acme.siret);
  });

  test("update par id et par champ unique", async () => {
    const c = await db.client.create({ data: acme });
    await db.client.update({ where: { id: c.id }, data: { iban: "NOUVEL-IBAN" } });
    assert.equal((await db.client.findUnique({ where: { id: c.id } }))?.iban, "NOUVEL-IBAN");

    // where sur l'index : l'extension retrouve l'id pour l'AAD
    const idx = (await db.$queryRawUnsafe<any[]>(`SELECT "siretIdx" FROM "Client"`))[0].siretIdx;
    await db.client.update({ where: { siretIdx: idx }, data: { notes: { set: "via index" } } });
    assert.equal((await db.client.findUnique({ where: { id: c.id } }))?.notes, "via index");

    // changer le SIRET met l'index à jour
    await db.client.update({ where: { id: c.id }, data: { siret: "99999999999999" } });
    assert.equal((await db.client.findFirst({ where: { siret: "99999999999999" } }))?.id, c.id);
  });

  test("updateMany sur un champ chiffré : un chiffré par ligne", async () => {
    await db.client.create({ data: { ...acme, siret: "1" } });
    await db.client.create({ data: { ...acme, siret: "2" } });
    const res = await db.client.updateMany({ where: { name: "ACME" }, data: { notes: "commun" } });
    assert.equal(res.count, 2);
    const raw = await db.$queryRawUnsafe<any[]>(`SELECT notes FROM "Client"`);
    assert.notEqual(raw[0].notes, raw[1].notes);
    assert.ok((await db.client.findMany()).every((c) => c.notes === "commun"));
  });

  test("createMany et upsert", async () => {
    await db.client.createMany({ data: [{ ...acme, siret: "1" }, { ...acme, siret: "2" }] });
    assert.equal((await db.client.findFirst({ where: { siret: "2" } }))?.iban, acme.iban);

    const id = crypto.randomUUID();
    await db.client.upsert({ where: { id }, create: { id, ...acme, siret: "3" }, update: {} });
    await db.client.upsert({ where: { id }, create: { id, ...acme, siret: "3" }, update: { notes: "mis à jour" } });
    assert.equal((await db.client.findUnique({ where: { id } }))?.notes, "mis à jour");
  });

  test("écriture imbriquée vers un champ chiffré : refusée plutôt qu'écrite en clair", async () => {
    await assert.rejects(
      db.client.create({ data: { ...acme, invoices: { create: { amount: 1, label: "secret" } } } }),
      /imbriquée/,
    );
    const raw = await db.$queryRawUnsafe<any[]>(`SELECT * FROM "Invoice"`);
    assert.equal(raw.length, 0);
  });

  test("chiffré copié vers une autre ligne : illisible", async () => {
    const a = await db.client.create({ data: { ...acme, siret: "1" } });
    const b = await db.client.create({ data: { ...acme, siret: "2", iban: "AUTRE" } });
    await db.$executeRawUnsafe(`UPDATE "Client" SET iban = (SELECT iban FROM "Client" WHERE id = $1) WHERE id = $2`, a.id, b.id);
    await assert.rejects(db.client.findUnique({ where: { id: b.id } }), /Échec du déchiffrement/);
  });

  test("valeur en clair injectée en base : refusée", async () => {
    const c = await db.client.create({ data: acme });
    await db.$executeRawUnsafe(`UPDATE "Client" SET notes = 'injecté' WHERE id = $1`, c.id);
    await assert.rejects(db.client.findUnique({ where: { id: c.id } }), /n'est pas chiffré/);
  });

  test("rotation de clé", async () => {
    const c = await db.client.create({ data: acme });
    await db.invoice.create({ data: { clientId: c.id, amount: 1, label: "L" } });

    const db2 = mod.createPrismaClient(await k1k2(), DATABASE_URL);
    try {
      assert.equal(await db2.$rotateEncryptionKeys(1), 2);
      const raw = await db2.$queryRawUnsafe<any[]>(`SELECT siret, iban, notes FROM "Client"`);
      for (const v of Object.values(raw[0])) assert.match(String(v), /^v1\.k2\./);
      assert.equal((await db2.client.findUnique({ where: { id: c.id }, include: { invoices: true } }))?.invoices[0].label, "L");
      assert.equal(await db2.$rotateEncryptionKeys(), 0);
    } finally {
      await db2.$disconnect();
    }
  });
});
