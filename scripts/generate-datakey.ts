/**
 * Génère une data key AES-256 via OKMS et affiche UNIQUEMENT sa version chiffrée.
 *
 * Usage :
 *   npx tsx scripts/generate-datakey.ts k1
 *
 * Copie la sortie dans FIELD_KEYS (ou BLIND_INDEX_KEY) et dans ton gestionnaire
 * de mots de passe. La version en clair n'est jamais affichée ni écrite.
 */
import "reflect-metadata";
import { OkmsClient } from "../src/crypto/okms.client";

async function main() {
  const name = process.argv[2];
  if (!name) throw new Error("Usage : npx tsx scripts/generate-datakey.ts <nom>");
  const { wrapped, plaintext } = await new OkmsClient().generateDataKey(name);
  plaintext.fill(0);
  console.log(`${name}:${wrapped}`);
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
