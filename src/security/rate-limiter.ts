/**
 * Rate limiter for gateway authentication to prevent brute-force attacks.
 * Uses a sliding window approach with exponential backoff for repeated failures.
 */

export type RateLimitConfig = {
  /** Maximum failed attempts before lockout */
  maxAttempts: number;
  /** Base window in milliseconds for tracking attempts */
  windowMs: number;
  /** Lockout duration in milliseconds after max attempts exceeded */
  lockoutMs: number;
  /** Enable exponential backoff for repeated lockouts */
  exponentialBackoff: boolean;
  /** Maximum lockout duration in milliseconds (caps exponential backoff) */
  maxLockoutMs: number;
};

export type RateLimitEntry = {
  attempts: number;
  firstAttemptAt: number;
  lastAttemptAt: number;
  lockedUntil: number;
  lockoutCount: number;
};

export type RateLimitResult = {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  lockedUntil?: number;
  reason?: "rate_limited" | "locked_out";
};

const DEFAULT_CONFIG: RateLimitConfig = {
  maxAttempts: 5,
  windowMs: 60_000, // 1 minute
  lockoutMs: 300_000, // 5 minutes
  exponentialBackoff: true,
  maxLockoutMs: 3_600_000, // 1 hour max
};

export class RateLimiter {
  private entries: Map<string, RateLimitEntry> = new Map();
  private config: RateLimitConfig;
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor(config: Partial<RateLimitConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    // Cleanup stale entries every 5 minutes
    this.cleanupInterval = setInterval(() => this.cleanup(), 300_000);
  }

  /**
   * Check if a request from the given key is allowed.
   * Call this BEFORE processing the authentication attempt.
   */
  check(key: string): RateLimitResult {
    const now = Date.now();
    const entry = this.entries.get(key);

    if (!entry) {
      return {
        allowed: true,
        remaining: this.config.maxAttempts,
        resetAt: now + this.config.windowMs,
      };
    }

    // Check if currently locked out
    if (entry.lockedUntil > now) {
      return {
        allowed: false,
        remaining: 0,
        resetAt: entry.lockedUntil,
        lockedUntil: entry.lockedUntil,
        reason: "locked_out",
      };
    }

    // Check if window has expired (reset attempts)
    if (now - entry.firstAttemptAt > this.config.windowMs) {
      this.entries.delete(key);
      return {
        allowed: true,
        remaining: this.config.maxAttempts,
        resetAt: now + this.config.windowMs,
      };
    }

    // Check if at or over limit
    if (entry.attempts >= this.config.maxAttempts) {
      return {
        allowed: false,
        remaining: 0,
        resetAt: entry.firstAttemptAt + this.config.windowMs,
        reason: "rate_limited",
      };
    }

    return {
      allowed: true,
      remaining: this.config.maxAttempts - entry.attempts,
      resetAt: entry.firstAttemptAt + this.config.windowMs,
    };
  }

  /**
   * Record a failed authentication attempt.
   * Call this AFTER a failed authentication.
   */
  recordFailure(key: string): RateLimitResult {
    const now = Date.now();
    let entry = this.entries.get(key);

    if (!entry || now - entry.firstAttemptAt > this.config.windowMs) {
      // Start fresh window
      entry = {
        attempts: 1,
        firstAttemptAt: now,
        lastAttemptAt: now,
        lockedUntil: 0,
        lockoutCount: entry?.lockoutCount ?? 0,
      };
      this.entries.set(key, entry);
      return {
        allowed: true,
        remaining: this.config.maxAttempts - 1,
        resetAt: now + this.config.windowMs,
      };
    }

    entry.attempts += 1;
    entry.lastAttemptAt = now;

    // Check if this triggers a lockout
    if (entry.attempts >= this.config.maxAttempts) {
      entry.lockoutCount += 1;
      let lockoutDuration = this.config.lockoutMs;

      if (this.config.exponentialBackoff && entry.lockoutCount > 1) {
        // Exponential backoff: double the lockout for each subsequent lockout
        lockoutDuration = Math.min(
          this.config.lockoutMs * Math.pow(2, entry.lockoutCount - 1),
          this.config.maxLockoutMs,
        );
      }

      entry.lockedUntil = now + lockoutDuration;
      entry.attempts = 0; // Reset attempts for next window after lockout
      entry.firstAttemptAt = now;

      return {
        allowed: false,
        remaining: 0,
        resetAt: entry.lockedUntil,
        lockedUntil: entry.lockedUntil,
        reason: "locked_out",
      };
    }

    return {
      allowed: true,
      remaining: this.config.maxAttempts - entry.attempts,
      resetAt: entry.firstAttemptAt + this.config.windowMs,
    };
  }

  /**
   * Record a successful authentication (resets the failure count).
   */
  recordSuccess(key: string): void {
    const entry = this.entries.get(key);
    if (entry) {
      // Keep lockout history but reset attempts
      entry.attempts = 0;
      entry.firstAttemptAt = Date.now();
      // Gradually reduce lockout count on success
      if (entry.lockoutCount > 0) {
        entry.lockoutCount = Math.max(0, entry.lockoutCount - 1);
      }
    }
  }

  /**
   * Manually reset rate limit for a key (e.g., after admin intervention).
   */
  reset(key: string): void {
    this.entries.delete(key);
  }

  /**
   * Get current state for a key (useful for debugging/monitoring).
   */
  getState(key: string): RateLimitEntry | undefined {
    return this.entries.get(key);
  }

  /**
   * Clean up expired entries to prevent memory leaks.
   */
  private cleanup(): void {
    const now = Date.now();
    const expireThreshold = this.config.windowMs + this.config.maxLockoutMs;

    for (const [key, entry] of this.entries) {
      const age = now - entry.lastAttemptAt;
      if (age > expireThreshold && entry.lockedUntil < now) {
        this.entries.delete(key);
      }
    }
  }

  /**
   * Stop the cleanup interval (call when shutting down).
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.entries.clear();
  }

  /**
   * Get statistics for monitoring.
   */
  getStats(): { totalEntries: number; lockedEntries: number } {
    const now = Date.now();
    let lockedEntries = 0;
    for (const entry of this.entries.values()) {
      if (entry.lockedUntil > now) {
        lockedEntries += 1;
      }
    }
    return {
      totalEntries: this.entries.size,
      lockedEntries,
    };
  }
}

// Singleton instance for gateway authentication
let gatewayRateLimiter: RateLimiter | null = null;

export function getGatewayRateLimiter(): RateLimiter {
  if (!gatewayRateLimiter) {
    gatewayRateLimiter = new RateLimiter({
      maxAttempts: 5,
      windowMs: 60_000, // 1 minute
      lockoutMs: 300_000, // 5 minutes initial lockout
      exponentialBackoff: true,
      maxLockoutMs: 3_600_000, // 1 hour max
    });
  }
  return gatewayRateLimiter;
}

/**
 * Extract a rate limit key from an HTTP request.
 * Uses IP address as the primary identifier.
 */
export function extractRateLimitKey(params: {
  remoteAddress?: string;
  forwardedFor?: string;
  trustedProxies?: string[];
}): string {
  const { remoteAddress, forwardedFor, trustedProxies = [] } = params;

  // If we have a forwarded-for header and the remote is a trusted proxy,
  // use the first IP in the chain (original client)
  if (forwardedFor && remoteAddress) {
    const isTrusted = trustedProxies.some((proxy) => {
      if (proxy.includes("/")) {
        // CIDR notation - simplified check
        return remoteAddress.startsWith(
          proxy.split("/")[0]?.split(".").slice(0, 2).join(".") ?? "",
        );
      }
      return remoteAddress === proxy;
    });

    if (isTrusted) {
      const clientIp = forwardedFor.split(",")[0]?.trim();
      if (clientIp) return `ip:${clientIp}`;
    }
  }

  return `ip:${remoteAddress ?? "unknown"}`;
}

// For testing purposes
export function __resetGatewayRateLimiterForTest(): void {
  if (gatewayRateLimiter) {
    gatewayRateLimiter.destroy();
    gatewayRateLimiter = null;
  }
}
