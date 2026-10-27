import { describe, expect, it } from "vitest";

import { filter, score, type Command } from "./palette";

const cmds: Command[] = [
  { id: "go-security", group: "Go to", title: "Security" },
  { id: "scan-security", group: "Actions", title: "Run security scan", keywords: "malware threats" },
  { id: "go-clean", group: "Go to", title: "Clean", keywords: "caches junk" },
  { id: "mode-trash", group: "Actions", title: "Move deleted items to the Trash", keywords: "delete mode" },
  { id: "nm", group: "Actions", title: "Find old node_modules", keywords: "npm projects" },
];

describe("palette matching", () => {
  it("shows everything for an empty query, in order", () => {
    expect(filter(cmds, "").map((c) => c.id)).toEqual(cmds.map((c) => c.id));
  });

  it("ranks title starts above words inside the title", () => {
    expect(filter(cmds, "sec").map((c) => c.id)).toEqual(["go-security", "scan-security"]);
  });

  it("finds by keyword and needs every word", () => {
    expect(filter(cmds, "malware").map((c) => c.id)).toEqual(["scan-security"]);
    expect(filter(cmds, "junk").map((c) => c.id)).toEqual(["go-clean"]);
    expect(filter(cmds, "delete trash").map((c) => c.id)).toEqual(["mode-trash"]);
    expect(filter(cmds, "delete purple")).toEqual([]);
  });

  it("is case-insensitive and treats regex characters literally", () => {
    expect(score("NODE_M", cmds[4])).toBeGreaterThan(0);
    expect(score("(", cmds[0])).toBe(0);
  });
});
