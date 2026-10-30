import { Injectable, OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";
import { OkmsClient } from "./okms.client";

/**
 * Chiffrement par champ (AES-256-GCM) + index aveugle (HMAC-SHA256).
 *
 * Les clés en clair n'existent qu'en mémoire : au démarrage, les data keys
 * emballées (env) sont déchiffrées par OKMS. Un dump de la base ne contient
 * que des chiffrés, et la config que des clés chiffrées.
 *
 * Format stocké : v1.<keyId>.<iv>.<ciphertext>.<tag>  (base64url)
 */
@Injectable()
export class CryptoService implements OnModuleInit, OnModuleDestroy {
  private keys = new Map<string, Buffer>();
  private currentKeyId!: string;
  private indexKey!: Buffer;

  constructor(private readonly okms: OkmsClient) {}

  async onModuleInit() {
    // FIELD_KEYS="k1:<clé emballée>,k2:<clé emballée>" ; FIELD_KEY_CURRENT=k2
    const entries = requireEnv("FIELD_KEYS").split(",").map((e) => {
      const i = e.indexOf(":");
      return [e.slice(0, i).trim(), e.slice(i + 1).trim()] as const;
    });
    for (const [id, wrapped] of entries) {
      this.keys.set(id, await this.okms.unwrapDataKey(wrapped));
    }
    this.currentKeyId = requireEnv("FIELD_KEY_CURRENT");
    if (!this.keys.has(this.currentKeyId)) {
      throw new Error(`FIELD_KEY_CURRENT=${this.currentKeyId} absent de FIELD_KEYS`);
    }
    // Clé d'index séparée : elle ne tourne pas avec les clés de chiffrement,
    // sinon il faudrait recalculer tous les index à chaque rotation.
    this.indexKey = await this.okms.unwrapDataKey(requireEnv("BLIND_INDEX_KEY"));
  }

  onModuleDestroy() {
    for (const k of this.keys.values()) k.fill(0);
    this.indexKey?.fill(0);
  }

  /**
   * @param aad contexte lié au chiffré, ex. "Client.iban.<id>".
   *   Un chiffré copié vers une autre ligne ou une autre colonne ne se déchiffre plus.
   */
  encrypt(plaintext: string, aad: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.keys.get(this.currentKeyId)!, iv);
    cipher.setAAD(Buffer.from(aad, "utf8"));
    const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    return ["v1", this.currentKeyId, b64(iv), b64(ct), b64(cipher.getAuthTag())].join(".");
  }

  decrypt(blob: string, aad: string): string {
    const [version, keyId, iv, ct, tag] = blob.split(".");
    if (version !== "v1" || !tag) throw new Error("Format de chiffré inconnu");
    const key = this.keys.get(keyId);
    if (!key) throw new Error(`Clé ${keyId} inconnue : ajoute-la à FIELD_KEYS`);
    const decipher = createDecipheriv("aes-256-gcm", key, unb64(iv));
    decipher.setAAD(Buffer.from(aad, "utf8"));
    decipher.setAuthTag(unb64(tag));
    // Lève une erreur si le chiffré ou l'AAD a été modifié
    return Buffer.concat([decipher.update(unb64(ct)), decipher.final()]).toString("utf8");
  }

  encryptNullable(v: string | null | undefined, aad: string) {
    return v == null ? v : this.encrypt(v, aad);
  }

  decryptNullable(v: string | null | undefined, aad: string) {
    return v == null ? v : this.decrypt(v, aad);
  }

  /** Vrai si le chiffré n'utilise pas la clé courante (à re-chiffrer). */
  needsRotation(blob: string): boolean {
    return blob.split(".")[1] !== this.currentKeyId;
  }

  /**
   * Index aveugle pour les recherches exactes. Le `scope` évite que deux
   * colonnes contenant la même valeur aient le même index.
   */
  blindIndex(value: string, scope: string): string {
    const normalized = value.normalize("NFKC").trim().toLowerCase().replace(/\s+/g, "");
    return createHmac("sha256", this.indexKey).update(`${scope}\u0000${normalized}`).digest("base64url");
  }
}

const b64 = (b: Buffer) => b.toString("base64url");
const unb64 = (s: string) => Buffer.from(s, "base64url");

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Variable d'environnement manquante : ${name}`);
  return v;
}
