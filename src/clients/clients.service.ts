import { Inject, Injectable } from "@nestjs/common";
import { PRISMA, PrismaDb } from "../prisma/prisma.module";

/**
 * Code métier ordinaire : aucune ligne de chiffrement ici, l'extension
 * Prisma s'en charge. siret, iban, notes et Invoice.label sont pourtant
 * chiffrés en base.
 */
@Injectable()
export class ClientsService {
  constructor(@Inject(PRISMA) private readonly db: PrismaDb) {}

  create(data: { name: string; siret: string; iban?: string | null; notes?: string | null }) {
    // id et siretIdx sont remplis par l'extension
    return this.db.client.create({ data });
  }

  findBySiret(siret: string) {
    // Réécrit en `where: { siretIdx: HMAC(siret) }` par l'extension
    return this.db.client.findFirst({ where: { siret }, include: { invoices: true } });
  }

  list() {
    return this.db.client.findMany({ orderBy: { name: "asc" } });
  }

  addInvoice(clientId: string, amount: number, label: string) {
    return this.db.invoice.create({ data: { clientId, amount, label } });
  }

  rotateKeys() {
    return this.db.$rotateEncryptionKeys();
  }
}
