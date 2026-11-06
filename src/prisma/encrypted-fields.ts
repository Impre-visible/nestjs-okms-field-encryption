import type { Prisma } from "../generated/prisma/client";
import type { EncryptedFieldOptions } from "./field-encryption.extension";

/**
 * Champs chiffrés, par modèle. C'est le seul endroit à modifier pour chiffrer
 * un nouveau champ (puis migrer les données existantes, voir README).
 *
 * `index` : colonne qui reçoit l'index aveugle, pour permettre
 * `where: { siret: "..." }`. Sans index, impossible de filtrer sur le champ.
 */
export const encryptedFields = {
  Client: {
    siret: { index: "siretIdx" },
    iban: {},
    notes: {},
  },
  Invoice: {
    label: {},
  },
} satisfies { [M in Prisma.ModelName]?: Record<string, EncryptedFieldOptions> };
