import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import {
  encrypt,
  decrypt,
  isEncrypted,
  readEncryptedJson,
  writeEncryptedJson,
  migrateToEncrypted,
} from "./credential-encryption.js";

describe("credential-encryption", () => {
  let testDir: string;
  let testKey: Buffer;

  beforeEach(async () => {
    testDir = await fs.mkdtemp(path.join(os.tmpdir(), "moltbot-crypt-test-"));
    testKey = crypto.randomBytes(32);
  });

  afterEach(async () => {
    await fs.rm(testDir, { recursive: true, force: true });
  });

  describe("encrypt/decrypt", () => {
    it("should encrypt and decrypt a string", async () => {
      const plaintext = "Hello, World!";
      const encrypted = await encrypt(plaintext, { key: testKey });
      const decrypted = await decrypt(encrypted, { key: testKey });

      expect(decrypted).toBe(plaintext);
    });

    it("should encrypt and decrypt JSON data", async () => {
      const data = { username: "test", token: "secret-token-123" };
      const plaintext = JSON.stringify(data);
      const encrypted = await encrypt(plaintext, { key: testKey });
      const decrypted = await decrypt(encrypted, { key: testKey });

      expect(JSON.parse(decrypted)).toEqual(data);
    });

    it("should produce different ciphertext for same plaintext", async () => {
      const plaintext = "Same content";
      const encrypted1 = await encrypt(plaintext, { key: testKey });
      const encrypted2 = await encrypt(plaintext, { key: testKey });

      expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext);
      expect(encrypted1.iv).not.toBe(encrypted2.iv);
    });

    it("should fail decryption with wrong key", async () => {
      const plaintext = "Secret data";
      const encrypted = await encrypt(plaintext, { key: testKey });
      const wrongKey = crypto.randomBytes(32);

      await expect(decrypt(encrypted, { key: wrongKey })).rejects.toThrow("Decryption failed");
    });

    it("should fail decryption with tampered ciphertext", async () => {
      const plaintext = "Secret data";
      const encrypted = await encrypt(plaintext, { key: testKey });

      // Tamper with ciphertext
      const tamperedCiphertext = Buffer.from(encrypted.ciphertext, "base64");
      tamperedCiphertext[0] ^= 0xff;
      encrypted.ciphertext = tamperedCiphertext.toString("base64");

      await expect(decrypt(encrypted, { key: testKey })).rejects.toThrow("Decryption failed");
    });

    it("should fail decryption with tampered auth tag", async () => {
      const plaintext = "Secret data";
      const encrypted = await encrypt(plaintext, { key: testKey });

      // Tamper with auth tag
      const tamperedAuthTag = Buffer.from(encrypted.authTag, "base64");
      tamperedAuthTag[0] ^= 0xff;
      encrypted.authTag = tamperedAuthTag.toString("base64");

      await expect(decrypt(encrypted, { key: testKey })).rejects.toThrow("Decryption failed");
    });
  });

  describe("isEncrypted", () => {
    it("should return true for encrypted data", async () => {
      const encrypted = await encrypt("test", { key: testKey });
      expect(isEncrypted(encrypted)).toBe(true);
    });

    it("should return false for plain object", () => {
      expect(isEncrypted({ foo: "bar" })).toBe(false);
    });

    it("should return false for null/undefined", () => {
      expect(isEncrypted(null)).toBe(false);
      expect(isEncrypted(undefined)).toBe(false);
    });

    it("should return false for string", () => {
      expect(isEncrypted("hello")).toBe(false);
    });
  });

  describe("readEncryptedJson/writeEncryptedJson", () => {
    it("should write and read encrypted JSON", async () => {
      const data = { credentials: { key: "secret-value" } };
      const filePath = path.join(testDir, "encrypted.json");

      await writeEncryptedJson(filePath, data, { key: testKey });
      const result = await readEncryptedJson(filePath, { key: testKey });

      expect(result).toEqual(data);
    });

    it("should set restrictive file permissions", async () => {
      const filePath = path.join(testDir, "encrypted.json");
      await writeEncryptedJson(filePath, { test: true }, { key: testKey });

      const stats = await fs.stat(filePath);
      const mode = stats.mode & 0o777;
      expect(mode).toBe(0o600);
    });

    it("should return null for non-existent file", async () => {
      const filePath = path.join(testDir, "nonexistent.json");
      const result = await readEncryptedJson(filePath, { key: testKey });
      expect(result).toBeNull();
    });

    it("should read unencrypted JSON for backward compatibility", async () => {
      const data = { legacy: true, value: 123 };
      const filePath = path.join(testDir, "plain.json");
      await fs.writeFile(filePath, JSON.stringify(data));

      const result = await readEncryptedJson(filePath, { key: testKey });
      expect(result).toEqual(data);
    });
  });

  describe("migrateToEncrypted", () => {
    it("should migrate unencrypted file to encrypted", async () => {
      const data = { sensitive: "data", token: "abc123" };
      const filePath = path.join(testDir, "migrate.json");
      await fs.writeFile(filePath, JSON.stringify(data));

      const result = await migrateToEncrypted(filePath, { key: testKey });

      expect(result.migrated).toBe(true);
      expect(result.backupPath).toBeDefined();

      // Verify encrypted file
      const migrated = await readEncryptedJson(filePath, { key: testKey });
      expect(migrated).toEqual(data);

      // Verify backup exists
      const backupExists = await fs
        .access(result.backupPath!)
        .then(() => true)
        .catch(() => false);
      expect(backupExists).toBe(true);
    });

    it("should not migrate already encrypted file", async () => {
      const data = { already: "encrypted" };
      const filePath = path.join(testDir, "already-encrypted.json");
      await writeEncryptedJson(filePath, data, { key: testKey });

      const result = await migrateToEncrypted(filePath, { key: testKey });

      expect(result.migrated).toBe(false);
      expect(result.backupPath).toBeUndefined();
    });

    it("should return false for non-existent file", async () => {
      const filePath = path.join(testDir, "nonexistent.json");
      const result = await migrateToEncrypted(filePath, { key: testKey });
      expect(result.migrated).toBe(false);
    });
  });
});
