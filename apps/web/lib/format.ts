// 표시용 순수 함수 — vitest 대상.
export const VERDICTS = ["allow", "alert", "transform", "require_approval", "block"] as const;
export type Verdict = (typeof VERDICTS)[number];

export function p95(values: number[]): number {
  if (!values.length) return 0;
  const s = [...values].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.ceil(0.95 * s.length) - 1)];
}

export function shortHash(h?: string | null, n = 8): string {
  if (!h) return "—";
  return h.length <= n + 2 ? h : `${h.slice(0, n)}…`;
}

export function fmtTime(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (x: number) => String(x).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function standardChips(standards: Record<string, { version: string; ids: string[] }> | undefined): string[] {
  // CMP-09: 판본 필수 표기 — "LLM01 · 2026"
  if (!standards) return [];
  return Object.values(standards).flatMap((s) => s.ids.map((id) => `${id} · ${s.version}`));
}

export function gateStats(records: { body: { gate: string; latencyMs: number; budgetMs: number | null; degraded: string[] } }[]) {
  const by: Record<string, { lat: number[]; budget: number | null; degraded: number; n: number }> = {};
  for (const r of records) {
    const g = (by[r.body.gate] ??= { lat: [], budget: r.body.budgetMs, degraded: 0, n: 0 });
    g.lat.push(r.body.latencyMs);
    g.n += 1;
    g.degraded += r.body.degraded?.length ? 1 : 0;
  }
  return Object.fromEntries(
    Object.entries(by).map(([g, v]) => {
      const p = p95(v.lat);
      const status = v.budget == null ? "ok" : p > v.budget ? "over" : p > v.budget * 0.9 ? "near" : "ok";
      return [g, { p95: p, budget: v.budget, n: v.n, degraded: v.degraded, status }];
    }),
  );
}
