/**
 * Credential encryption utilities for secure storage of sensitive data.
 * Uses AES-256-GCM for authenticated encryption with a machine-derived key.
 */

import crypto from "node:crypto";
import fs from "node:fs/promises";
import fsSync from "node:fs";
import path from "node:path";
import os from "node:os";

export type EncryptedData = {
  version: 1;
  algorithm: "aes-256-gcm";
  iv: string; // base64
  authTag: string; // base64
  ciphertext: string; // base64
  keyDerivation: {
    method: "pbkdf2";
    salt: string; // base64
    iterations: number;
  };
};

export type EncryptionConfig = {
  /** Custom encryption key (if not provided, derived from machine ID) */
  key?: Buffer;
  /** Path to store the key salt file */
  saltPath?: string;
  /** PBKDF2 iterations (higher = more secure but slower) */
  iterations?: number;
};

const ALGORITHM = "aes-256-gcm";
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 16; // 128 bits for GCM
const AUTH_TAG_LENGTH = 16; // 128 bits
const DEFAULT_ITERATIONS = 100_000;
const SALT_LENGTH = 32;

/**
 * Get a machine-specific identifier for key derivation.
 * Combines multiple system attributes for uniqueness.
 */
function getMachineIdentifier(): string {
  const components = [
    os.hostname(),
    os.platform(),
    os.arch(),
    os.homedir(),
    // Add user-specific component
    process.env.USER ?? process.env.USERNAME ?? "default",
  ];

  // Create a stable hash of machine components
  return crypto.createHash("sha256").update(components.join(":")).digest("hex");
}

/**
 * Derive an encryption key from the machine identifier and salt.
 */
async function deriveKey(params: {
  salt: Buffer;
  iterations: number;
  machineId?: string;
}): Promise<Buffer> {
  const machineId = params.machineId ?? getMachineIdentifier();

  return new Promise((resolve, reject) => {
    crypto.pbkdf2(machineId, params.salt, params.iterations, KEY_LENGTH, "sha512", (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
}

/**
 * Get or create the salt for key derivation.
 */
async function getOrCreateSalt(saltPath: string): Promise<Buffer> {
  try {
    const existing = await fs.readFile(saltPath);
    if (existing.length === SALT_LENGTH) {
      return existing;
    }
  } catch {
    // Salt doesn't exist, create it
  }

  const salt = crypto.randomBytes(SALT_LENGTH);
  await fs.mkdir(path.dirname(saltPath), { recursive: true, mode: 0o700 });
  await fs.writeFile(saltPath, salt, { mode: 0o600 });
  return salt;
}

/**
 * Encrypt data using AES-256-GCM with a derived key.
 */
export async function encrypt(
  plaintext: string,
  config: EncryptionConfig = {},
): Promise<EncryptedData> {
  const iterations = config.iterations ?? DEFAULT_ITERATIONS;
  const saltPath = config.saltPath ?? path.join(os.homedir(), ".moltbot", ".encryption-salt");

  let key: Buffer;
  let salt: Buffer;

  if (config.key) {
    key = config.key;
    salt = crypto.randomBytes(SALT_LENGTH);
  } else {
    salt = await getOrCreateSalt(saltPath);
    key = await deriveKey({ salt, iterations });
  }

  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);

  const authTag = cipher.getAuthTag();

  return {
    version: 1,
    algorithm: ALGORITHM,
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    ciphertext: encrypted.toString("base64"),
    keyDerivation: {
      method: "pbkdf2",
      salt: salt.toString("base64"),
      iterations,
    },
  };
}

/**
 * Decrypt data encrypted with the encrypt function.
 */
export async function decrypt(data: EncryptedData, config: EncryptionConfig = {}): Promise<string> {
  if (data.version !== 1) {
    throw new Error(`Unsupported encryption version: ${data.version}`);
  }

  if (data.algorithm !== ALGORITHM) {
    throw new Error(`Unsupported algorithm: ${data.algorithm}`);
  }

  const saltPath = config.saltPath ?? path.join(os.homedir(), ".moltbot", ".encryption-salt");
  const salt = Buffer.from(data.keyDerivation.salt, "base64");
  const iterations = data.keyDerivation.iterations;

  let key: Buffer;
  if (config.key) {
    key = config.key;
  } else {
    // For decryption, we use the salt from the encrypted data
    key = await deriveKey({ salt, iterations });
  }

  const iv = Buffer.from(data.iv, "base64");
  const authTag = Buffer.from(data.authTag, "base64");
  const ciphertext = Buffer.from(data.ciphertext, "base64");

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  try {
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString("utf8");
  } catch (err) {
    throw new Error("Decryption failed: invalid key or corrupted data");
  }
}

/**
 * Check if data appears to be encrypted (has the expected structure).
 */
export function isEncrypted(data: unknown): data is EncryptedData {
  if (!data || typeof data !== "object") return false;
  const obj = data as Record<string, unknown>;
  return (
    obj.version === 1 &&
    obj.algorithm === ALGORITHM &&
    typeof obj.iv === "string" &&
    typeof obj.authTag === "string" &&
    typeof obj.ciphertext === "string" &&
    typeof obj.keyDerivation === "object"
  );
}

/**
 * Read and decrypt a JSON file.
 */
export async function readEncryptedJson<T>(
  filePath: string,
  config: EncryptionConfig = {},
): Promise<T | null> {
  try {
    const raw = await fs.readFile(filePath, "utf-8");
    const parsed = JSON.parse(raw);

    if (isEncrypted(parsed)) {
      const decrypted = await decrypt(parsed, config);
      return JSON.parse(decrypted) as T;
    }

    // Not encrypted, return as-is (for backward compatibility)
    return parsed as T;
  } catch {
    return null;
  }
}

/**
 * Encrypt and write a JSON file.
 */
export async function writeEncryptedJson(
  filePath: string,
  data: unknown,
  config: EncryptionConfig = {},
): Promise<void> {
  const plaintext = JSON.stringify(data, null, 2);
  const encrypted = await encrypt(plaintext, config);

  await fs.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
  await fs.writeFile(filePath, JSON.stringify(encrypted, null, 2), { mode: 0o600 });
}

/**
 * Migrate an unencrypted JSON file to encrypted format.
 * Creates a backup of the original file.
 */
export async function migrateToEncrypted(
  filePath: string,
  config: EncryptionConfig = {},
): Promise<{ migrated: boolean; backupPath?: string }> {
  try {
    const raw = await fs.readFile(filePath, "utf-8");
    const parsed = JSON.parse(raw);

    // Already encrypted
    if (isEncrypted(parsed)) {
      return { migrated: false };
    }

    // Create backup
    const backupPath = `${filePath}.unencrypted.bak`;
    await fs.copyFile(filePath, backupPath);
    await fs.chmod(backupPath, 0o600);

    // Write encrypted version
    await writeEncryptedJson(filePath, parsed, config);

    return { migrated: true, backupPath };
  } catch {
    return { migrated: false };
  }
}

/**
 * Synchronous check if a file exists and contains encrypted data.
 */
export function isFileEncryptedSync(filePath: string): boolean {
  try {
    if (!fsSync.existsSync(filePath)) return false;
    const raw = fsSync.readFileSync(filePath, "utf-8");
    const parsed = JSON.parse(raw);
    return isEncrypted(parsed);
  } catch {
    return false;
  }
}

/**
 * Rotate the encryption key (re-encrypt all data with a new salt).
 * Useful for security policy compliance or after potential key compromise.
 */
export async function rotateEncryptionKey(
  filePaths: string[],
  config: EncryptionConfig = {},
): Promise<{ rotated: string[]; failed: string[] }> {
  const saltPath = config.saltPath ?? path.join(os.homedir(), ".moltbot", ".encryption-salt");

  // Read all files first
  const contents: Map<string, unknown> = new Map();
  for (const filePath of filePaths) {
    const data = await readEncryptedJson(filePath, config);
    if (data !== null) {
      contents.set(filePath, data);
    }
  }

  // Generate new salt
  const newSalt = crypto.randomBytes(SALT_LENGTH);
  await fs.writeFile(saltPath, newSalt, { mode: 0o600 });

  // Re-encrypt all files
  const rotated: string[] = [];
  const failed: string[] = [];

  for (const [filePath, data] of contents) {
    try {
      await writeEncryptedJson(filePath, data, config);
      rotated.push(filePath);
    } catch {
      failed.push(filePath);
    }
  }

  return { rotated, failed };
}
