import { describe, expect, it } from "vitest";
import { gateStats, p95, shortHash, standardChips } from "@/lib/format";
import { cellLabel, counts, grid, type RiskItem } from "@/lib/riskmap";
import { parseLang, t } from "@/lib/i18n";

describe("format", () => {
  it("p95", () => {
    expect(p95([])).toBe(0);
    expect(p95([5])).toBe(5);
    expect(p95(Array.from({ length: 100 }, (_, i) => i + 1))).toBe(95);
  });
  it("shortHash", () => {
    expect(shortHash("abcdef0123456789")).toBe("abcdef01…");
    expect(shortHash(null)).toBe("—");
  });
  it("standard chips carry version (CMP-09)", () => {
    expect(standardChips({ "owasp-llm": { version: "2026", ids: ["LLM01", "LLM08"] } })).toEqual(["LLM01 · 2026", "LLM08 · 2026"]);
  });
  it("gate stats status by budget", () => {
    const mk = (gate: string, latencyMs: number, budgetMs: number | null) => ({ body: { gate, latencyMs, budgetMs, degraded: [] } });
    const s = gateStats([mk("tool", 25, 20), mk("tool", 25, 20), mk("input", 10, 80), mk("output", 140, 150)]);
    expect(s.tool.status).toBe("over");
    expect(s.input.status).toBe("ok");
    expect(s.output.status).toBe("near");
  });
});

describe("risk map", () => {
  const it_ = (id: string, kind: "item" | "gap" = "item"): RiskItem => ({
    id, kind, domain: kind === "gap" ? null : id.split("-")[0], nameEn: id, nameKo: id, priority: "P0",
    series: "C1", stage: 1, agent: null, agentStatus: null, state: "missing",
  });
  it("orders numerically and separates gaps", () => {
    const g = grid([it_("D10-02"), it_("D1-02"), it_("D1-01"), it_("X10", "gap"), it_("X02", "gap")]);
    expect(g.rows[0].cells.map((c) => c.id)).toEqual(["D1-01", "D1-02"]);
    expect(g.rows[9].cells.map((c) => c.id)).toEqual(["D10-02"]);
    expect(g.gaps.map((c) => c.id)).toEqual(["X02", "X10"]);
  });
  it("cell label and counts", () => {
    expect(cellLabel("D1-05")).toBe("1-05");
    expect(cellLabel("X05")).toBe("X05");
    expect(counts([it_("D1-01"), it_("D1-02")])).toEqual({ missing: 2 });
  });
});

describe("i18n", () => {
  it("ko default, en switch", () => {
    expect(parseLang(undefined)).toBe("ko");
    expect(t("ko", "evidence")).toBe("증적 원장");
    expect(t(parseLang("en"), "evidence")).toBe("Evidence ledger");
  });
});
