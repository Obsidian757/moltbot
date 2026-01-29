import fsSync from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";

import { resolveOAuthDir } from "../config/paths.js";
import { info, success } from "../globals.js";
import { getChildLogger } from "../logging.js";
import { DEFAULT_ACCOUNT_ID } from "../routing/session-key.js";
import { defaultRuntime, type RuntimeEnv } from "../runtime.js";
import { formatCliCommand } from "../cli/command-format.js";
import type { WebChannel } from "../utils.js";
import { jidToE164, resolveUserPath } from "../utils.js";
import {
  decrypt,
  encrypt,
  isEncrypted,
  type EncryptedData,
  type EncryptionConfig,
} from "../security/credential-encryption.js";

/** Configuration for credential encryption */
export type WebAuthEncryptionOptions = {
  /** Enable encryption for credential storage */
  enabled: boolean;
  /** Custom encryption configuration */
  config?: EncryptionConfig;
};

export function resolveDefaultWebAuthDir(): string {
  return path.join(resolveOAuthDir(), "whatsapp", DEFAULT_ACCOUNT_ID);
}

export const WA_WEB_AUTH_DIR = resolveDefaultWebAuthDir();

export function resolveWebCredsPath(authDir: string): string {
  return path.join(authDir, "creds.json");
}

export function resolveWebCredsBackupPath(authDir: string): string {
  return path.join(authDir, "creds.json.bak");
}

export function hasWebCredsSync(authDir: string): boolean {
  try {
    const stats = fsSync.statSync(resolveWebCredsPath(authDir));
    return stats.isFile() && stats.size > 1;
  } catch {
    return false;
  }
}

function readCredsJsonRaw(filePath: string): string | null {
  try {
    if (!fsSync.existsSync(filePath)) return null;
    const stats = fsSync.statSync(filePath);
    if (!stats.isFile() || stats.size <= 1) return null;
    return fsSync.readFileSync(filePath, "utf-8");
  } catch {
    return null;
  }
}

/**
 * Read credentials from file, automatically handling encrypted or plain format.
 */
export async function readWebCreds<T = unknown>(
  authDir: string,
  encryptionConfig?: EncryptionConfig,
): Promise<T | null> {
  const credsPath = resolveWebCredsPath(resolveUserPath(authDir));
  try {
    const raw = await fs.readFile(credsPath, "utf-8");
    const parsed = JSON.parse(raw);

    if (isEncrypted(parsed)) {
      const decrypted = await decrypt(parsed, encryptionConfig);
      return JSON.parse(decrypted) as T;
    }

    return parsed as T;
  } catch {
    return null;
  }
}

/**
 * Write credentials to file with optional encryption.
 */
export async function writeWebCreds(
  authDir: string,
  data: unknown,
  options?: WebAuthEncryptionOptions,
): Promise<void> {
  const resolvedAuthDir = resolveUserPath(authDir);
  const credsPath = resolveWebCredsPath(resolvedAuthDir);

  await fs.mkdir(resolvedAuthDir, { recursive: true, mode: 0o700 });

  if (options?.enabled) {
    const plaintext = JSON.stringify(data, null, 2);
    const encrypted = await encrypt(plaintext, options.config);
    await fs.writeFile(credsPath, JSON.stringify(encrypted, null, 2), { mode: 0o600 });
  } else {
    await fs.writeFile(credsPath, JSON.stringify(data, null, 2), { mode: 0o600 });
  }
}

/**
 * Check if credentials are currently stored in encrypted format.
 */
export function isWebCredsEncrypted(authDir: string): boolean {
  try {
    const credsPath = resolveWebCredsPath(resolveUserPath(authDir));
    const raw = readCredsJsonRaw(credsPath);
    if (!raw) return false;
    const parsed = JSON.parse(raw);
    return isEncrypted(parsed);
  } catch {
    return false;
  }
}

/**
 * Migrate unencrypted credentials to encrypted format.
 * Creates a backup of the original unencrypted file.
 */
export async function migrateWebCredsToEncrypted(
  authDir: string,
  encryptionConfig?: EncryptionConfig,
): Promise<{ migrated: boolean; backupPath?: string }> {
  const logger = getChildLogger({ module: "web-session" });
  const resolvedAuthDir = resolveUserPath(authDir);
  const credsPath = resolveWebCredsPath(resolvedAuthDir);

  try {
    const raw = await fs.readFile(credsPath, "utf-8");
    const parsed = JSON.parse(raw);

    // Already encrypted
    if (isEncrypted(parsed)) {
      return { migrated: false };
    }

    // Create backup of unencrypted file
    const backupPath = path.join(resolvedAuthDir, "creds.unencrypted.bak");
    await fs.copyFile(credsPath, backupPath);
    await fs.chmod(backupPath, 0o600);

    // Write encrypted version
    await writeWebCreds(authDir, parsed, { enabled: true, config: encryptionConfig });

    logger.info({ credsPath }, "migrated WhatsApp credentials to encrypted format");
    return { migrated: true, backupPath };
  } catch (err) {
    logger.error({ err, credsPath }, "failed to migrate credentials to encrypted format");
    return { migrated: false };
  }
}

/**
 * Securely delete the unencrypted backup after successful migration.
 */
export async function deleteUnencryptedBackup(authDir: string): Promise<boolean> {
  const resolvedAuthDir = resolveUserPath(authDir);
  const backupPath = path.join(resolvedAuthDir, "creds.unencrypted.bak");

  try {
    await fs.rm(backupPath, { force: true });
    return true;
  } catch {
    return false;
  }
}

export function maybeRestoreCredsFromBackup(authDir: string): void {
  const logger = getChildLogger({ module: "web-session" });
  try {
    const credsPath = resolveWebCredsPath(authDir);
    const backupPath = resolveWebCredsBackupPath(authDir);
    const raw = readCredsJsonRaw(credsPath);
    if (raw) {
      // Validate that creds.json is parseable.
      JSON.parse(raw);
      return;
    }

    const backupRaw = readCredsJsonRaw(backupPath);
    if (!backupRaw) return;

    // Ensure backup is parseable before restoring.
    JSON.parse(backupRaw);
    fsSync.copyFileSync(backupPath, credsPath);
    logger.warn({ credsPath }, "restored corrupted WhatsApp creds.json from backup");
  } catch {
    // ignore
  }
}

export async function webAuthExists(
  authDir: string = resolveDefaultWebAuthDir(),
  encryptionConfig?: EncryptionConfig,
) {
  const resolvedAuthDir = resolveUserPath(authDir);
  maybeRestoreCredsFromBackup(resolvedAuthDir);
  const credsPath = resolveWebCredsPath(resolvedAuthDir);
  try {
    await fs.access(resolvedAuthDir);
  } catch {
    return false;
  }
  try {
    const stats = await fs.stat(credsPath);
    if (!stats.isFile() || stats.size <= 1) return false;
    const raw = await fs.readFile(credsPath, "utf-8");
    const parsed = JSON.parse(raw);

    // Handle encrypted credentials
    if (isEncrypted(parsed)) {
      try {
        await decrypt(parsed, encryptionConfig);
        return true;
      } catch {
        // Decryption failed - credentials exist but can't be read
        return false;
      }
    }

    // Plain credentials are valid if parseable
    return true;
  } catch {
    return false;
  }
}

async function clearLegacyBaileysAuthState(authDir: string) {
  const entries = await fs.readdir(authDir, { withFileTypes: true });
  const shouldDelete = (name: string) => {
    if (name === "oauth.json") return false;
    if (name === "creds.json" || name === "creds.json.bak") return true;
    if (!name.endsWith(".json")) return false;
    return /^(app-state-sync|session|sender-key|pre-key)-/.test(name);
  };
  await Promise.all(
    entries.map(async (entry) => {
      if (!entry.isFile()) return;
      if (!shouldDelete(entry.name)) return;
      await fs.rm(path.join(authDir, entry.name), { force: true });
    }),
  );
}

export async function logoutWeb(params: {
  authDir?: string;
  isLegacyAuthDir?: boolean;
  runtime?: RuntimeEnv;
}) {
  const runtime = params.runtime ?? defaultRuntime;
  const resolvedAuthDir = resolveUserPath(params.authDir ?? resolveDefaultWebAuthDir());
  const exists = await webAuthExists(resolvedAuthDir);
  if (!exists) {
    runtime.log(info("No WhatsApp Web session found; nothing to delete."));
    return false;
  }
  if (params.isLegacyAuthDir) {
    await clearLegacyBaileysAuthState(resolvedAuthDir);
  } else {
    await fs.rm(resolvedAuthDir, { recursive: true, force: true });
  }
  runtime.log(success("Cleared WhatsApp Web credentials."));
  return true;
}

export function readWebSelfId(authDir: string = resolveDefaultWebAuthDir()) {
  // Read the cached WhatsApp Web identity (jid + E.164) from disk if present.
  // Note: This is synchronous and does not support encrypted credentials.
  // Use readWebSelfIdAsync for encrypted credential support.
  try {
    const credsPath = resolveWebCredsPath(resolveUserPath(authDir));
    if (!fsSync.existsSync(credsPath)) {
      return { e164: null, jid: null } as const;
    }
    const raw = fsSync.readFileSync(credsPath, "utf-8");
    const parsed = JSON.parse(raw) as { me?: { id?: string }; version?: number } | undefined;

    // Skip if encrypted (version field indicates encrypted format)
    if (parsed && "version" in parsed && parsed.version === 1) {
      return { e164: null, jid: null, encrypted: true } as const;
    }

    const jid = parsed?.me?.id ?? null;
    const e164 = jid ? jidToE164(jid, { authDir }) : null;
    return { e164, jid } as const;
  } catch {
    return { e164: null, jid: null } as const;
  }
}

/**
 * Async version of readWebSelfId that supports encrypted credentials.
 */
export async function readWebSelfIdAsync(
  authDir: string = resolveDefaultWebAuthDir(),
  encryptionConfig?: EncryptionConfig,
): Promise<{ e164: string | null; jid: string | null }> {
  try {
    const creds = await readWebCreds<{ me?: { id?: string } }>(authDir, encryptionConfig);
    if (!creds) {
      return { e164: null, jid: null };
    }
    const jid = creds.me?.id ?? null;
    const e164 = jid ? jidToE164(jid, { authDir }) : null;
    return { e164, jid };
  } catch {
    return { e164: null, jid: null };
  }
}

/**
 * Return the age (in milliseconds) of the cached WhatsApp web auth state, or null when missing.
 * Helpful for heartbeats/observability to spot stale credentials.
 */
export function getWebAuthAgeMs(authDir: string = resolveDefaultWebAuthDir()): number | null {
  try {
    const stats = fsSync.statSync(resolveWebCredsPath(resolveUserPath(authDir)));
    return Date.now() - stats.mtimeMs;
  } catch {
    return null;
  }
}

export function logWebSelfId(
  authDir: string = resolveDefaultWebAuthDir(),
  runtime: RuntimeEnv = defaultRuntime,
  includeChannelPrefix = false,
) {
  // Human-friendly log of the currently linked personal web session.
  const { e164, jid } = readWebSelfId(authDir);
  const details = e164 || jid ? `${e164 ?? "unknown"}${jid ? ` (jid ${jid})` : ""}` : "unknown";
  const prefix = includeChannelPrefix ? "Web Channel: " : "";
  runtime.log(info(`${prefix}${details}`));
}

export async function pickWebChannel(
  pref: WebChannel | "auto",
  authDir: string = resolveDefaultWebAuthDir(),
): Promise<WebChannel> {
  const choice: WebChannel = pref === "auto" ? "web" : pref;
  const hasWeb = await webAuthExists(authDir);
  if (!hasWeb) {
    throw new Error(
      `No WhatsApp Web session found. Run \`${formatCliCommand("moltbot channels login --channel whatsapp --verbose")}\` to link.`,
    );
  }
  return choice;
}
