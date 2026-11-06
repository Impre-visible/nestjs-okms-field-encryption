import { randomUUID } from "node:crypto";
import { Prisma } from "@prisma/client/extension";

/**
 * Extension Prisma de chiffrement par champ, transparente pour le code métier :
 *
 *   await db.client.create({ data: { name: "ACME", siret: "123..." } })  // chiffré en base
 *   await db.client.findFirst({ where: { siret: "123..." } })            // via l'index aveugle
 *   (await db.client.findMany()).map(c => c.siret)                       // déchiffré
 *
 * Le chiffré est lié à sa ligne : AAD = "<Modèle>.<champ>.<id>".
 * Chaque modèle chiffré doit donc avoir un `id` de type String.
 */

export interface FieldCrypto {
  encrypt(plaintext: string, aad: string): string;
  decrypt(blob: string, aad: string): string;
  blindIndex(value: string, scope: string): string;
  needsRotation(blob: string): boolean;
}

export interface EncryptedFieldOptions {
  /** Nom de la colonne qui reçoit l'index aveugle (recherche exacte possible). */
  index?: string;
}

export type EncryptedFieldsConfig = Partial<Record<string, Record<string, EncryptedFieldOptions>>>;

export interface FieldEncryptionOptions {
  /**
   * Laisse passer les valeurs encore en clair à la lecture (migration de données
   * existantes). À désactiver une fois la migration faite.
   */
  allowPlaintext?: boolean;
}

export class FieldEncryptionError extends Error {
  override name = "FieldEncryptionError";
}

const ID = "id";
const CIPHERTEXT = /^v1\.[\w-]+\.[\w-]+\.[\w-]*\.[\w-]+$/;
const NESTED_WRITE_OPS = ["create", "createMany", "connectOrCreate", "upsert", "update", "updateMany"];

export function fieldEncryption(
  crypto: FieldCrypto,
  config: EncryptedFieldsConfig,
  options: FieldEncryptionOptions = {},
) {
  // Pour chaque nom de champ chiffré, les modèles qui l'utilisent
  const modelsByField = new Map<string, string[]>();
  for (const [model, fields] of Object.entries(config)) {
    for (const field of Object.keys(fields ?? {})) {
      modelsByField.set(field, [...(modelsByField.get(field) ?? []), model]);
    }
  }

  const fieldsOf = (model: string) => config[model] ?? {};
  const aad = (model: string, field: string, id: string) => `${model}.${field}.${id}`;
  const scope = (model: string, field: string) => `${model}.${field}`;

  // ---------- Écriture ----------

  function encryptData(model: string, data: Record<string, any>, id: string) {
    const out = { ...data };
    for (const [field, opts] of Object.entries(fieldsOf(model))) {
      if (!(field in out)) continue;
      let value = out[field];
      if (isPlainObject(value) && "set" in value) value = value.set;
      if (value === undefined) continue;
      if (value === null) {
        out[field] = null;
        if (opts.index) out[opts.index] = null;
        continue;
      }
      if (typeof value !== "string") {
        throw new FieldEncryptionError(`${model}.${field} : seuls les champs String peuvent être chiffrés`);
      }
      out[field] = crypto.encrypt(value, aad(model, field, id));
      if (opts.index) out[opts.index] = crypto.blindIndex(value, scope(model, field));
    }
    assertNoNestedEncryptedWrite(model, out);
    return out;
  }

  function touchesEncrypted(model: string, data: unknown) {
    return isPlainObject(data) && Object.keys(fieldsOf(model)).some((f) => f in data);
  }

  /** Les écritures imbriquées vers un modèle chiffré ne sont pas gérées : on refuse plutôt que d'écrire en clair. */
  function assertNoNestedEncryptedWrite(model: string, data: Record<string, any>) {
    for (const [key, value] of Object.entries(data)) {
      if (!isPlainObject(value)) continue;
      if (!NESTED_WRITE_OPS.some((op) => op in value)) continue;
      const hit = findEncryptedKey(value);
      if (hit) {
        throw new FieldEncryptionError(
          `${model}.${key} : écriture imbriquée touchant un champ chiffré (${hit}). ` +
            `Écris ce modèle avec son propre appel (ou dans une $transaction).`,
        );
      }
    }
  }

  // ---------- Filtres ----------

  function rewriteWhere(model: string, where: any): any {
    if (!isPlainObject(where)) return where;
    const fields = fieldsOf(model);
    const out: Record<string, any> = {};

    for (const [key, value] of Object.entries(where)) {
      if (key === "AND" || key === "OR" || key === "NOT") {
        out[key] = Array.isArray(value) ? value.map((w) => rewriteWhere(model, w)) : rewriteWhere(model, value);
        continue;
      }

      const opts = fields[key];
      if (!opts) {
        // Filtre relationnel vers un champ chiffré : il ne matcherait jamais, on refuse
        const hit = isPlainObject(value) ? findEncryptedKey(value) : undefined;
        if (hit) {
          throw new FieldEncryptionError(
            `${model}.${key} : filtre relationnel sur un champ chiffré (${hit}) non géré. ` +
              `Filtre directement sur le modèle concerné.`,
          );
        }
        out[key] = value;
        continue;
      }

      // Tests de nullité : la valeur reste null en base, rien à réécrire
      if (value === null || (isPlainObject(value) && Object.keys(value).length === 1 && (value.equals === null || value.not === null))) {
        out[key] = value;
        continue;
      }

      if (!opts.index) {
        throw new FieldEncryptionError(`${model}.${key} est chiffré sans index : impossible de filtrer dessus`);
      }
      const toIndex = (v: unknown) => {
        if (typeof v !== "string") throw new FieldEncryptionError(`${model}.${key} : valeur de filtre invalide`);
        return crypto.blindIndex(v, scope(model, key));
      };

      if (typeof value === "string") out[opts.index] = toIndex(value);
      else if (isPlainObject(value) && onlyKeys(value, ["equals"])) out[opts.index] = toIndex(value.equals);
      else if (isPlainObject(value) && onlyKeys(value, ["in"])) out[opts.index] = { in: value.in.map(toIndex) };
      else if (isPlainObject(value) && onlyKeys(value, ["notIn"])) out[opts.index] = { notIn: value.notIn.map(toIndex) };
      else if (isPlainObject(value) && onlyKeys(value, ["not"]) && typeof value.not === "string") out[opts.index] = { not: toIndex(value.not) };
      else {
        throw new FieldEncryptionError(
          `${model}.${key} est chiffré : seuls l'égalité, not, in et notIn sont possibles (via l'index aveugle)`,
        );
      }
    }
    return out;
  }

  function assertNotSortedOrGrouped(model: string, args: any) {
    const encrypted = Object.keys(fieldsOf(model));
    if (!encrypted.length || !args) return;
    const orderBy = Array.isArray(args.orderBy) ? args.orderBy : args.orderBy ? [args.orderBy] : [];
    const by = Array.isArray(args.by) ? args.by : args.by ? [args.by] : [];
    const distinct = Array.isArray(args.distinct) ? args.distinct : args.distinct ? [args.distinct] : [];
    const used = [
      ...orderBy.flatMap((o: object) => Object.keys(o)),
      ...by,
      ...distinct,
      ...["_min", "_max", "_count"].flatMap((k) => (isPlainObject(args[k]) ? Object.keys(args[k]) : [])),
    ];
    const hit = used.find((f: string) => encrypted.includes(f));
    if (hit) {
      throw new FieldEncryptionError(`${model}.${hit} est chiffré : impossible de trier, grouper ou agréger dessus`);
    }
  }

  // ---------- Lecture ----------

  /** L'id sert d'AAD : on le sélectionne d'office dès qu'un champ chiffré est demandé. */
  function ensureIds(selection: any): any {
    if (!isPlainObject(selection)) return selection;
    const out: Record<string, any> = { ...selection };
    if (Object.keys(out).some((k) => modelsByField.has(k) && out[k]) && !out[ID]) out[ID] = true;
    for (const [k, v] of Object.entries(out)) {
      if (!isPlainObject(v)) continue;
      const nested = { ...v };
      if (nested.select) nested.select = ensureIds(nested.select);
      if (nested.include) nested.include = ensureIds(nested.include);
      if (nested.where && findEncryptedKey(nested.where)) {
        throw new FieldEncryptionError(`${k} : filtre sur un champ chiffré dans une relation incluse non géré`);
      }
      out[k] = nested;
    }
    return out;
  }

  function decryptResult(value: any, model?: string): any {
    if (Array.isArray(value)) return value.map((v) => decryptResult(v, model));
    if (!isPlainObject(value)) return value;
    const out: Record<string, any> = { ...value };
    for (const [key, v] of Object.entries(out)) {
      const isOwnField = model !== undefined && fieldsOf(model)[key] !== undefined;
      if (typeof v === "string" && (isOwnField || modelsByField.has(key))) {
        if (CIPHERTEXT.test(v)) {
          out[key] = decryptField(key, v, out[ID], isOwnField ? model : undefined);
        } else if (isOwnField && !options.allowPlaintext) {
          throw new FieldEncryptionError(`${model}.${key} (id ${out[ID]}) n'est pas chiffré en base`);
        }
      } else if (v !== null && typeof v === "object") {
        out[key] = decryptResult(v);
      }
    }
    return out;
  }

  function decryptField(field: string, blob: string, id: unknown, model?: string) {
    if (typeof id !== "string") {
      throw new FieldEncryptionError(`Impossible de déchiffrer ${field} sans l'id de la ligne`);
    }
    // Dans une relation incluse on ne connaît pas le modèle : l'AAD tranche
    for (const m of model ? [model] : modelsByField.get(field) ?? []) {
      try {
        return crypto.decrypt(blob, aad(m, field, id));
      } catch {
        /* candidat suivant */
      }
    }
    throw new FieldEncryptionError(`Échec du déchiffrement de ${field} (id ${id}) : clé absente ou donnée altérée`);
  }

  function findEncryptedKey(value: unknown): string | undefined {
    if (Array.isArray(value)) {
      for (const v of value) {
        const hit = findEncryptedKey(v);
        if (hit) return hit;
      }
      return undefined;
    }
    if (!isPlainObject(value)) return undefined;
    for (const [k, v] of Object.entries(value)) {
      if (modelsByField.has(k)) return k;
      const hit = findEncryptedKey(v);
      if (hit) return hit;
    }
    return undefined;
  }

  // ---------- Extension ----------

  return Prisma.defineExtension((client) => {
    // `client` est le client SANS cette extension : on l'utilise pour les
    // recherches d'id et les mises à jour ligne par ligne (données déjà chiffrées).
    const base = client as any;
    const delegate = (model: string) => base[lowerFirst(model)];

    return client.$extends({
      name: "field-encryption",

      client: {
        /** Re-chiffre avec la clé courante toutes les valeurs encore sur une ancienne clé. */
        async $rotateEncryptionKeys(batchSize = 500): Promise<number> {
          let rotated = 0;
          for (const [model, fields] of Object.entries(config)) {
            const names = Object.keys(fields ?? {});
            if (!names.length) continue;
            let cursor: string | undefined;
            for (;;) {
              const rows: any[] = await delegate(model).findMany({
                take: batchSize,
                ...(cursor && { skip: 1, cursor: { [ID]: cursor } }),
                orderBy: { [ID]: "asc" },
                select: { [ID]: true, ...Object.fromEntries(names.map((f) => [f, true])) },
              });
              if (!rows.length) break;
              for (const row of rows) {
                const data: Record<string, string> = {};
                for (const f of names) {
                  const v = row[f];
                  if (typeof v === "string" && CIPHERTEXT.test(v) && crypto.needsRotation(v)) {
                    const a = aad(model, f, row[ID]);
                    data[f] = crypto.encrypt(crypto.decrypt(v, a), a);
                  }
                }
                if (Object.keys(data).length) {
                  await delegate(model).update({ where: { [ID]: row[ID] }, data });
                  rotated++;
                }
              }
              cursor = rows[rows.length - 1][ID];
            }
          }
          return rotated;
        },
      },

      query: {
        $allModels: {
          async $allOperations({ model, operation, args, query }) {
            const a: any = args ? { ...args } : {};
            const encrypted = Object.keys(fieldsOf(model)).length > 0;

            if (a.where) a.where = rewriteWhere(model, a.where);
            assertNotSortedOrGrouped(model, a);
            if (a.select) a.select = ensureIds(a.select);
            if (a.include) a.include = ensureIds(a.include);

            switch (operation) {
              case "create": {
                const id = encrypted ? (a.data[ID] ?? randomUUID()) : undefined;
                a.data = encrypted ? encryptData(model, { ...a.data, [ID]: id }, id) : guarded(model, a.data);
                break;
              }
              case "createMany":
              case "createManyAndReturn": {
                const rows = Array.isArray(a.data) ? a.data : [a.data];
                a.data = rows.map((row: any) => {
                  if (!encrypted) return guarded(model, row);
                  const id = row[ID] ?? randomUUID();
                  return encryptData(model, { ...row, [ID]: id }, id);
                });
                break;
              }
              case "update": {
                if (encrypted && touchesEncrypted(model, a.data)) {
                  const id = typeof a.where?.[ID] === "string" ? a.where[ID] : await findId(model, a.where);
                  a.data = encryptData(model, a.data, id);
                } else a.data = guarded(model, a.data);
                break;
              }
              case "upsert": {
                if (encrypted) {
                  const createId = a.create[ID] ?? randomUUID();
                  a.create = encryptData(model, { ...a.create, [ID]: createId }, createId);
                  if (touchesEncrypted(model, a.update)) {
                    const existing = await delegate(model).findUnique({ where: a.where, select: { [ID]: true } });
                    a.update = encryptData(model, a.update, existing?.[ID] ?? createId);
                  }
                } else {
                  a.create = guarded(model, a.create);
                  a.update = guarded(model, a.update);
                }
                break;
              }
              case "updateMany":
              case "updateManyAndReturn": {
                if (encrypted && touchesEncrypted(model, a.data)) {
                  // Un chiffré par ligne (AAD = id) : impossible en un seul UPDATE SQL
                  const rows: { id: string }[] = await delegate(model).findMany({
                    where: a.where,
                    select: { [ID]: true },
                    ...(a.limit !== undefined && { take: a.limit }),
                  });
                  const updated = await base.$transaction(
                    rows.map((r) =>
                      delegate(model).update({
                        where: { [ID]: r.id },
                        data: encryptData(model, a.data, r.id),
                        ...(operation === "updateManyAndReturn" && a.select && { select: a.select }),
                        ...(operation === "updateManyAndReturn" && a.omit && { omit: a.omit }),
                      }),
                    ),
                  );
                  return operation === "updateMany" ? { count: rows.length } : decryptResult(updated, model);
                }
                a.data = guarded(model, a.data);
                break;
              }
            }

            const result = await query(a);
            if (operation === "count" || operation === "aggregate" || operation === "groupBy") return result;
            return decryptResult(result, model);
          },
        },
      },
    });

    async function findId(model: string, where: unknown): Promise<string> {
      const row = await delegate(model).findUniqueOrThrow({ where, select: { [ID]: true } });
      return row[ID];
    }

    function guarded(model: string, data: any) {
      if (isPlainObject(data)) assertNoNestedEncryptedWrite(model, data);
      return data;
    }
  });
}

function isPlainObject(v: unknown): v is Record<string, any> {
  if (typeof v !== "object" || v === null) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function onlyKeys(obj: Record<string, unknown>, keys: string[]) {
  const k = Object.keys(obj);
  return k.length === keys.length && keys.every((x) => k.includes(x));
}

function lowerFirst(s: string) {
  return s.charAt(0).toLowerCase() + s.slice(1);
}
