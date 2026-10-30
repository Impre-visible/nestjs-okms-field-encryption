import { Module } from "@nestjs/common";
import { ClientsModule } from "./clients/clients.module";
import { CryptoModule } from "./crypto/crypto.module";
import { PrismaModule } from "./prisma/prisma.module";

@Module({
  // CryptoModule et PrismaModule sont globaux : à importer une seule fois ici.
  // Si OKMS est injoignable au démarrage, l'appli refuse de démarrer.
  imports: [PrismaModule, CryptoModule, ClientsModule],
})
export class AppModule {}
