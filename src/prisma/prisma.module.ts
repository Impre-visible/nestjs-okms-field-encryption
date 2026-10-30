import { Global, Inject, Module, OnApplicationShutdown } from "@nestjs/common";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "../generated/prisma/client";
import { CryptoService } from "../crypto/crypto.service";
import { encryptedFields } from "./encrypted-fields";
import { fieldEncryption, FieldCrypto } from "./field-encryption.extension";

/** Jeton d'injection du client Prisma étendu : `@Inject(PRISMA) db: PrismaDb`. */
export const PRISMA = Symbol("PRISMA");

export function createPrismaClient(crypto: FieldCrypto, databaseUrl = process.env.DATABASE_URL) {
  const adapter = new PrismaPg({ connectionString: databaseUrl });
  return new PrismaClient({ adapter }).$extends(fieldEncryption(crypto, encryptedFields));
}

export type PrismaDb = ReturnType<typeof createPrismaClient>;

@Global()
@Module({
  providers: [
    {
      provide: PRISMA,
      // CryptoService charge ses clés dans onModuleInit, avant la première requête
      useFactory: (crypto: CryptoService) => createPrismaClient(crypto),
      inject: [CryptoService],
    },
  ],
  exports: [PRISMA],
})
export class PrismaModule implements OnApplicationShutdown {
  constructor(@Inject(PRISMA) private readonly db: PrismaDb) {}

  async onApplicationShutdown() {
    await this.db.$disconnect();
  }
}
