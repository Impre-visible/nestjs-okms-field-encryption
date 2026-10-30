import { Injectable } from "@nestjs/common";
import { randomUUID } from "node:crypto";
import { PrismaService } from "../prisma/prisma.service";
import { CryptoService } from "../crypto/crypto.service";

/*
 * Schéma Prisma correspondant :
 *
 * model Client {
 *   id        String  @id                 // généré côté appli : il sert d'AAD
 *   name      String                      // en clair : nécessaire pour trier/afficher en liste
 *   siret     String                      // chiffré
 *   siretIdx  String  @unique             // index aveugle pour la recherche exacte
 *   iban      String?                     // chiffré
 *   notes     String?                     // chiffré
 * }
 */

export interface ClientInput {
  name: string;
  siret: string;
  iban?: string | null;
  notes?: string | null;
}

export interface Client extends ClientInput {
  id: string;
}

type ClientRow = {
  id: string;
  name: string;
  siret: string;
  siretIdx: string;
  iban: string | null;
  notes: string | null;
};

@Injectable()
export class ClientsRepository {
  constructor(
    private readonly prisma: PrismaService,
    private readonly crypto: CryptoService,
  ) {}

  async create(input: ClientInput): Promise<Client> {
    const id = randomUUID();
    const row = await this.prisma.client.create({ data: this.toRow(id, input) });
    return this.fromRow(row);
  }

  async update(id: string, input: ClientInput): Promise<Client> {
    const row = await this.prisma.client.update({ where: { id }, data: this.toRow(id, input) });
    return this.fromRow(row);
  }

  async findById(id: string): Promise<Client | null> {
    const row = await this.prisma.client.findUnique({ where: { id } });
    return row && this.fromRow(row);
  }

  /** Recherche exacte sur un champ chiffré, via l'index aveugle. */
  async findBySiret(siret: string): Promise<Client | null> {
    const row = await this.prisma.client.findUnique({
      where: { siretIdx: this.crypto.blindIndex(siret, "Client.siret") },
    });
    return row && this.fromRow(row);
  }

  /** Re-chiffre avec la clé courante les lignes encore sur une ancienne clé. */
  async rotateKeys(batchSize = 500): Promise<number> {
    let cursor: string | undefined;
    let rotated = 0;
    for (;;) {
      const rows: ClientRow[] = await this.prisma.client.findMany({
        take: batchSize,
        ...(cursor && { skip: 1, cursor: { id: cursor } }),
        orderBy: { id: "asc" },
      });
      if (rows.length === 0) return rotated;
      for (const row of rows) {
        const stale = [row.siret, row.iban, row.notes].some(
          (v) => v != null && this.crypto.needsRotation(v),
        );
        if (stale) {
          await this.update(row.id, this.fromRow(row));
          rotated++;
        }
      }
      cursor = rows[rows.length - 1].id;
    }
  }

  private toRow(id: string, input: ClientInput): ClientRow {
    const c = this.crypto;
    return {
      id,
      name: input.name,
      siret: c.encrypt(input.siret, `Client.siret.${id}`),
      siretIdx: c.blindIndex(input.siret, "Client.siret"),
      iban: c.encryptNullable(input.iban, `Client.iban.${id}`) ?? null,
      notes: c.encryptNullable(input.notes, `Client.notes.${id}`) ?? null,
    };
  }

  private fromRow(row: ClientRow): Client {
    const c = this.crypto;
    return {
      id: row.id,
      name: row.name,
      siret: c.decrypt(row.siret, `Client.siret.${row.id}`),
      iban: c.decryptNullable(row.iban, `Client.iban.${row.id}`) ?? null,
      notes: c.decryptNullable(row.notes, `Client.notes.${row.id}`) ?? null,
    };
  }
}
