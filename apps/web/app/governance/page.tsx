// 거버넌스 자체 점검 — 플랫폼 스냅샷에 D10·X03·X08~X10 을 실행 (SCR-N01·Q04 일부).
import Link from "next/link";
import { Banner, Kpi } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { runAssess } from "@/lib/actions";
import { api, safe } from "@/lib/api";
import { t, tr, LX } from "@/lib/i18n";
import { prefs } from "@/lib/session";

import { L } from "@/lib/i18n";

export default async function Governance({ searchParams }: { searchParams: Promise<{ msg?: string }> }) {
  const { lang } = await prefs();
  const { msg } = await searchParams;
  const [snap, last] = await Promise.all([safe(api("/v1/governance/snapshot"), null as any), safe(api("/v1/findings?limit=200"), { items: [] as any[], total: 0 })]);
  const s = snap.data;
  const gov = last.data.items.filter((f: any) => /^(D10-|X0[389]|X10)/.test(f.ruleId) && f.verdict !== "allow").slice(0, 12);
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupGov")} › ${t(lang, "governance")}`} title={tr(lang, "거버넌스 자체 점검", "Governance self-check")}
        actions={<form action={runAssess}><button className="btn btn-primary">{L(lang, "지금 점검")}</button></form>} />
      {msg && <div className="mb-3"><Banner tone={msg.startsWith(L(lang, "실패")) ? "danger" : "info"}>{L(lang, msg)}</Banner></div>}
      {s && (
        <div className="mb-4 grid grid-cols-5 gap-3">
          <Kpi label={L(lang, "정책")} value={s.policies.length} sub={s.policies.map((p: any) => `${p.id}@v${p.version}`).join(", ")} accent="var(--navy)" />
          <Kpi label={L(lang, "원장 무결성")} value={s.ledger.ok ? "✓" : "✗"} sub={L(lang, "{0}건 · 체크포인트 {1}", s.ledger.records.toLocaleString(), s.ledger.checkpoints)} accent="var(--verdict-allow)" />
          <Kpi label={L(lang, "보존 (설정/요구)")} value={L(lang, "{0}/{1}일", s.retention.configuredDays, s.retention.requiredDays || "-")} accent={s.retention.configuredDays < s.retention.requiredDays ? "var(--verdict-block)" : "var(--verdict-allow)"} />
          <Kpi label={L(lang, "24시간 관문 관측")} value={s.monitoring.gateRecords24h.toLocaleString()} sub={L(lang, "강등 {0}% · 수집기 {1}", (s.monitoring.degradedRate * 100).toFixed(2), s.monitoring.collector ? "✓" : "✗")} accent="var(--primary)" />
          <Kpi label={L(lang, "열린 사건")} value={s.incidents.length} sub={L(lang, "위험 등록 {0}건", s.riskRegister.length)} accent="var(--verdict-approval)" />
        </div>
      )}
      <h2 className="mb-2 font-semibold">{L(lang, "최근 거버넌스 발견")}</h2>
      <div className="card overflow-hidden">
        <table className="grid-table"><thead><tr><th>{L(lang, "규칙")}</th><th>{L(lang, "판정")}</th><th>{L(lang, "근거")}</th></tr></thead><tbody>
          {gov.length === 0 && <tr><td colSpan={3} className="text-muted">{t(lang, "noData")}</td></tr>}
          {gov.map((f: any) => <tr key={f.id}><td className="mono"><Link className="text-primary" href={`/findings/${f.id}`}>{LX(lang, f.ruleId)}</Link></td><td>{LX(lang, f.effectiveVerdict ?? f.verdict)}</td><td className="text-xs">{LX(lang, f.evidence[0]?.note)}</td></tr>)}
        </tbody></table>
      </div>
    </>
  );
}
