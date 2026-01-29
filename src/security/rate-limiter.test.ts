import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  RateLimiter,
  extractRateLimitKey,
  __resetGatewayRateLimiterForTest,
} from "./rate-limiter.js";

describe("RateLimiter", () => {
  let rateLimiter: RateLimiter;

  beforeEach(() => {
    vi.useFakeTimers();
    rateLimiter = new RateLimiter({
      maxAttempts: 3,
      windowMs: 60_000,
      lockoutMs: 300_000,
      exponentialBackoff: true,
      maxLockoutMs: 3_600_000,
    });
  });

  afterEach(() => {
    rateLimiter.destroy();
    vi.useRealTimers();
  });

  describe("check", () => {
    it("should allow first request", () => {
      const result = rateLimiter.check("test-key");
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(3);
    });

    it("should return correct remaining count after failures", () => {
      rateLimiter.recordFailure("test-key");
      const result = rateLimiter.check("test-key");
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(2);
    });

    it("should deny request when locked out", () => {
      rateLimiter.recordFailure("test-key");
      rateLimiter.recordFailure("test-key");
      rateLimiter.recordFailure("test-key"); // Triggers lockout

      const result = rateLimiter.check("test-key");
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("locked_out");
      expect(result.lockedUntil).toBeGreaterThan(Date.now());
    });
  });

  describe("recordFailure", () => {
    it("should increment attempt count", () => {
      rateLimiter.recordFailure("test-key");
      const state = rateLimiter.getState("test-key");
      expect(state?.attempts).toBe(1);
    });

    it("should trigger lockout after max attempts", () => {
      rateLimiter.recordFailure("test-key");
      rateLimiter.recordFailure("test-key");
      const result = rateLimiter.recordFailure("test-key");

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("locked_out");
    });

    it("should apply exponential backoff on repeated lockouts", () => {
      // First lockout
      for (let i = 0; i < 3; i++) rateLimiter.recordFailure("test-key");
      const firstLockout = rateLimiter.getState("test-key")?.lockedUntil ?? 0;

      // Advance past first lockout
      vi.advanceTimersByTime(300_001);

      // Second lockout
      for (let i = 0; i < 3; i++) rateLimiter.recordFailure("test-key");
      const secondLockout = rateLimiter.getState("test-key")?.lockedUntil ?? 0;

      // Second lockout should be longer (2x)
      const firstDuration = firstLockout - Date.now() + 300_001;
      const secondDuration = secondLockout - Date.now();
      expect(secondDuration).toBeGreaterThan(firstDuration);
    });
  });

  describe("recordSuccess", () => {
    it("should reset attempt count", () => {
      rateLimiter.recordFailure("test-key");
      rateLimiter.recordFailure("test-key");
      rateLimiter.recordSuccess("test-key");

      const state = rateLimiter.getState("test-key");
      expect(state?.attempts).toBe(0);
    });

    it("should gradually reduce lockout count", () => {
      // Trigger lockout
      for (let i = 0; i < 3; i++) rateLimiter.recordFailure("test-key");
      vi.advanceTimersByTime(300_001);

      const beforeSuccess = rateLimiter.getState("test-key")?.lockoutCount ?? 0;
      rateLimiter.recordSuccess("test-key");
      const afterSuccess = rateLimiter.getState("test-key")?.lockoutCount ?? 0;

      expect(afterSuccess).toBeLessThan(beforeSuccess);
    });
  });

  describe("reset", () => {
    it("should clear all state for a key", () => {
      rateLimiter.recordFailure("test-key");
      rateLimiter.reset("test-key");

      const result = rateLimiter.check("test-key");
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(3);
    });
  });

  describe("window expiration", () => {
    it("should reset after window expires", () => {
      rateLimiter.recordFailure("test-key");
      rateLimiter.recordFailure("test-key");

      // Advance past window
      vi.advanceTimersByTime(60_001);

      const result = rateLimiter.check("test-key");
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(3);
    });
  });

  describe("getStats", () => {
    it("should return correct statistics", () => {
      rateLimiter.recordFailure("key1");
      for (let i = 0; i < 3; i++) rateLimiter.recordFailure("key2"); // Locked

      const stats = rateLimiter.getStats();
      expect(stats.totalEntries).toBe(2);
      expect(stats.lockedEntries).toBe(1);
    });
  });
});

describe("extractRateLimitKey", () => {
  it("should use remote address by default", () => {
    const key = extractRateLimitKey({ remoteAddress: "192.168.1.1" });
    expect(key).toBe("ip:192.168.1.1");
  });

  it("should handle missing remote address", () => {
    const key = extractRateLimitKey({});
    expect(key).toBe("ip:unknown");
  });

  it("should use forwarded-for when remote is trusted proxy", () => {
    const key = extractRateLimitKey({
      remoteAddress: "10.0.0.1",
      forwardedFor: "203.0.113.50, 10.0.0.1",
      trustedProxies: ["10.0.0.1"],
    });
    expect(key).toBe("ip:203.0.113.50");
  });

  it("should ignore forwarded-for when remote is not trusted", () => {
    const key = extractRateLimitKey({
      remoteAddress: "192.168.1.1",
      forwardedFor: "203.0.113.50",
      trustedProxies: ["10.0.0.1"],
    });
    expect(key).toBe("ip:192.168.1.1");
  });
});

describe("__resetGatewayRateLimiterForTest", () => {
  it("should reset the singleton", () => {
    __resetGatewayRateLimiterForTest();
    // Should not throw
    expect(true).toBe(true);
  });
});
