import { Global, Module } from "@nestjs/common";
import { CryptoService } from "./crypto.service";
import { OkmsClient } from "./okms.client";

@Global()
@Module({
  providers: [OkmsClient, CryptoService],
  exports: [CryptoService],
})
export class CryptoModule {}
