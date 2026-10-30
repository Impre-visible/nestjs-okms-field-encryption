import { Injectable, Logger } from "@nestjs/common";
import { readFileSync } from "node:fs";
import { Agent, fetch } from "undici";

/**
 * Client minimal pour l'API REST régionale d'OVHcloud KMS (OKMS).
 * Authentification par certificat client (mTLS).
 *
 * Endpoints utilisés (doc OVHcloud "Using OVHcloud KMS", à revérifier sur le
 * Swagger de ta région : https://<region>.okms.ovh.net/swagger/) :
 *   POST /v1/servicekey/{keyId}/datakey          -> { key, plaintext }
 *   POST /v1/servicekey/{keyId}/datakey/decrypt  -> { plaintext }
 */
@Injectable()
export class OkmsClient {
  private readonly logger = new Logger(OkmsClient.name);
  private readonly agent: Agent;
  private readonly endpoint: string;
  private readonly keyId: string;

  constructor() {
    this.endpoint = requireEnv("OKMS_ENDPOINT").replace(/\/$/, "");
    this.keyId = requireEnv("OKMS_SERVICE_KEY_ID");
    this.agent = new Agent({
      connect: {
        cert: readFileSync(requireEnv("OKMS_CERT_PATH")),
        key: readFileSync(requireEnv("OKMS_KEY_PATH")),
      },
    });
  }

  /** Déchiffre une data key emballée. Renvoie 32 octets en mémoire. */
  async unwrapDataKey(wrapped: string): Promise<Buffer> {
    const body = await this.post<{ plaintext: string }>(
      `/v1/servicekey/${this.keyId}/datakey/decrypt`,
      { key: wrapped },
    );
    const key = Buffer.from(body.plaintext, "base64");
    if (key.length !== 32) {
      throw new Error(`OKMS a renvoyé une clé de ${key.length} octets, 32 attendus (AES-256)`);
    }
    return key;
  }

  /** Génère une nouvelle data key. Ne garde QUE `key` (la version chiffrée). */
  async generateDataKey(name: string): Promise<{ wrapped: string; plaintext: Buffer }> {
    const body = await this.post<{ key: string; plaintext: string }>(
      `/v1/servicekey/${this.keyId}/datakey`,
      { name, size: 256 },
    );
    return { wrapped: body.key, plaintext: Buffer.from(body.plaintext, "base64") };
  }

  private async post<T>(path: string, payload: unknown, attempts = 5): Promise<T> {
    for (let i = 1; ; i++) {
      try {
        const res = await fetch(`${this.endpoint}${path}`, {
          method: "POST",
          dispatcher: this.agent,
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        if (res.ok) return (await res.json()) as T;
        // 4xx = erreur de config (certificat, droits, clé) : inutile de réessayer
        if (res.status < 500) {
          throw new FatalError(`OKMS ${res.status} sur ${path} : ${await res.text()}`);
        }
        throw new Error(`OKMS ${res.status} sur ${path}`);
      } catch (err) {
        if (err instanceof FatalError || i >= attempts) throw err;
        const delay = 500 * 2 ** (i - 1);
        this.logger.warn(`OKMS indisponible (tentative ${i}/${attempts}), nouvel essai dans ${delay} ms`);
        await new Promise((r) => setTimeout(r, delay));
      }
    }
  }
}

class FatalError extends Error {}

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Variable d'environnement manquante : ${name}`);
  return v;
}
