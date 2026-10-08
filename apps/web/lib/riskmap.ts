// 위험 지도(SCR-B04) 격자 구성 — D1~D10 × 7 + X 보강 10.
export type RiskItem = {
  id: string; kind: "item" | "gap"; domain: string | null; nameEn: string; nameKo: string;
  priority: string; series: string; stage: number; agent: string | null; agentStatus: string | null; state: string;
};

export const DOMAIN_KO: Record<string, string> = {
  D1: "인젝션", D2: "데이터 유출", D3: "도구 오남용", D4: "모델 환각", D5: "접근 통제",
  D6: "자율 과잉", D7: "공급망", D8: "메모리", D9: "인프라", D10: "거버넌스",
};

export const DOMAIN_EN: Record<string, string> = {
  D1: "Injection", D2: "Data leakage", D3: "Tool misuse", D4: "Hallucination", D5: "Access control",
  D6: "Excessive autonomy", D7: "Supply chain", D8: "Memory", D9: "Infrastructure", D10: "Governance",
};

export function domainName(lang: "ko" | "en", d: string): string {
  return (lang === "en" ? DOMAIN_EN : DOMAIN_KO)[d] ?? d;
}

export function grid(items: RiskItem[], lang: "ko" | "en" = "ko"): { rows: { key: string; label: string; cells: RiskItem[] }[]; gaps: RiskItem[] } {
  const rows = Object.keys(DOMAIN_KO).map((d) => ({
    key: d,
    label: `${d} ${domainName(lang, d)}`,
    cells: items.filter((i) => i.domain === d).sort((a, b) => a.id.localeCompare(b.id, "en", { numeric: true })),
  }));
  const gaps = items.filter((i) => i.kind === "gap").sort((a, b) => a.id.localeCompare(b.id, "en", { numeric: true }));
  return { rows, gaps };
}

export function cellLabel(id: string): string {
  // D1-05 → 1-05, X05 → X05
  return id.startsWith("D") ? id.slice(1) : id;
}

export function counts(items: RiskItem[]) {
  const c: Record<string, number> = {};
  for (const i of items) c[i.state] = (c[i.state] ?? 0) + 1;
  return c;
}
