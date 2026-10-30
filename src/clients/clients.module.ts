import { Module } from "@nestjs/common";
import { ClientsRepository } from "./clients.repository";

@Module({
  providers: [ClientsRepository],
  exports: [ClientsRepository],
})
export class ClientsModule {}
