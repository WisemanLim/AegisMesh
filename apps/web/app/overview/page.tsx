// SCR-B03 개요 대시보드 — 판정·승인·커버리지·관문 p95·위험 영역 요약.
import Link from "next/link";
import { Kpi, Banner } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { gateStats } from "@/lib/format";
import { t, LX } from "@/lib/i18n";
import { DOMAIN_KO, domainName } from "@/lib/riskmap";
import { prefs } from "@/lib/session";

import { L } from "@/lib/i18n";

export default async function Overview() {
  const { lang } = await prefs();
  const [findings, blocked, appr, cov, gates] = await Promise.all([
    safe(api("/v1/findings?limit=500"), { total: 0, items: [] as any[] }),
    safe(api("/v1/findings?verdict=block&limit=1"), { total: 0, items: [] }),
    safe(api("/v1/approvals"), { items: [] as any[] }),
    safe(api("/v1/coverage"), null as any),
    safe(api("/v1/evidence?kind=gate&limit=200"), { items: [] as any[] }),
  ]);
  const incs = await safe(api("/v1/incidents"), { items: [] as any[] });
  const gs = gateStats(gates.data.items);
  const byDomain: Record<string, number> = {};
  for (const f of findings.data.items) {
    if (f.verdict === "allow") continue;
    const d = String(f.ruleId).split("-")[0].replace(/\..*/, "");
    byDomain[d] = (byDomain[d] ?? 0) + 1;
  }
  return (
    <>
      <PageHeader crumb={t(lang, "overview")} title={lang === "en" ? "Overview — security posture" : L(lang, "개요 — 보안 태세")} />
      {findings.error && <div className="mb-4"><Banner tone="danger">{L(lang, "API 연결 실패: ")}{LX(lang, findings.error)}</Banner></div>}
      <div className="grid grid-cols-5 gap-4">
        <Kpi label={L(lang, "판정 (전체)")} value={findings.data.total.toLocaleString()} sub={L(lang, "차단 {0}", blocked.data.total.toLocaleString())} accent="var(--navy)" />
        <Kpi label={L(lang, "승인 대기")} value={<Link href="/approvals">{appr.data.items.length}</Link>} sub={L(lang, "2인 승인")} accent="var(--verdict-approval)" />
        <Kpi label={L(lang, "커버리지 (엄격)")} value={cov.data ? `${cov.data.strict.implemented}/${cov.data.strict.total}` : "—"} sub={cov.data ? L(lang, "전체 {0}/{1}", cov.data.implemented, cov.data.total) : ""} accent="var(--verdict-allow)" />
        <Kpi label={L(lang, "열린 사건")} value={<Link href="/incidents">{incs.data.items.length}</Link>} sub={`critical ${incs.data.items.filter((i: any) => i.severity === "critical").length}`} accent="var(--primary)" />
        <Kpi label={L(lang, "강등")} value={gates.data.items.filter((g: any) => g.body.degraded?.length).length} sub={L(lang, "fail-closed/open 기록")} accent="var(--verdict-block)" />
      </div>
      <div className="mt-4 grid grid-cols-2 gap-4">
        <section className="card p-4">
          <h2 className="mb-3 font-semibold">{L(lang, "관문 상태 · p95 / 예산")}</h2>
          {["input", "tool", "output"].map((g) => {
            const s = (gs as any)[g];
            const pct = s?.budget ? Math.min(100, (s.p95 / s.budget) * 100) : 0;
            return (
              <div key={g} className="mb-3 flex items-center gap-3 text-sm">
                <span className="w-14">{g}</span>
                <div className="h-3 flex-1 rounded bg-[#eef0f4]">
                  <div className="h-3 rounded" style={{ width: `${Math.max(pct, s ? 1 : 0)}%`, background: s?.status === "over" ? "var(--verdict-block)" : s?.status === "near" ? "#e2b007" : "var(--verdict-allow)" }} />
                </div>
                <span className="w-48 text-right text-xs text-muted">{s ? L(lang, "{0}ms / {1}ms · {2}건", s.p95.toFixed(2), s.budget, s.n) : L(lang, "관측 없음")}</span>
              </div>
            );
          })}
        </section>
        <section className="card p-4">
          <h2 className="mb-3 font-semibold">{L(lang, "위험 영역 10 · 비허용 판정 수")}</h2>
          <div className="grid grid-cols-5 gap-2">
            {Object.keys(DOMAIN_KO).map((d) => (
              <Link key={d} href={`/findings?domain=${d}`} className="rounded-lg border border-line p-2 text-center hover:border-primary">
                <div className="text-xs text-muted">{d} {domainName(lang, d)}</div>
                <div className="text-lg font-bold">{LX(lang, byDomain[d] ?? 0)}</div>
              </Link>
            ))}
          </div>
          <p className="mt-2 text-xs text-muted">{L(lang, "보강 X: ")}{Object.entries(byDomain).filter(([k]) => k.startsWith("X")).reduce((n, [, v]) => n + v, 0)}{L(lang, "건 · 최근 판정 500건 기준")}</p>
        </section>
      </div>
    </>
  );
}
