import { describe, expect, it } from "vitest";

import { orbLayout } from "./layout";

describe("orbLayout", () => {
  it("keeps the bubbles around the orb when there's room", () => {
    expect(orbLayout(640)).toEqual({ compact: false, orbSize: 350 });
    expect(orbLayout(434).compact).toBe(false); // 1200×800 window
  });

  it("moves the bubbles under the orb when the stage is narrow", () => {
    const l = orbLayout(368);
    expect(l.compact).toBe(true);
    expect(l.orbSize).toBeLessThanOrEqual(300);
    expect(orbLayout(200).orbSize).toBe(220);
  });
});
