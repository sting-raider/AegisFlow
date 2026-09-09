import { describe, expect, it } from "vitest";
import { ApiRequestError, retryStartupQuery } from "./api";

describe("startup query retries", () => {
  it("retries temporary gateway and connection failures", () => {
    expect(retryStartupQuery(0, new ApiRequestError(503, "Unavailable"))).toBe(true);
    expect(retryStartupQuery(3, new TypeError("Failed to fetch"))).toBe(true);
  });

  it("fails fast for application errors and caps startup retries", () => {
    expect(retryStartupQuery(0, new ApiRequestError(500, "Internal Error"))).toBe(false);
    expect(retryStartupQuery(20, new TypeError("Failed to fetch"))).toBe(false);
  });
});
