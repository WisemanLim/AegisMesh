// SCR-O01 판정 목록.
import Link from "next/link";
import { SeverityBadge, VerdictBadge } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime, shortHash } from "@/lib/format";
import { t, tr, LX } from "@/lib/i18n";
import { prefs } from "@/lib/session";

import { L } from "@/lib/i18n";

export default async function Findings({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const { lang } = await prefs();
  const sp = await searchParams;
  const q = new URLSearchParams();
  for (const k of ["verdict", "agent", "trace"]) if (sp[k]) q.set(k, sp[k]!);
  q.set("limit", "200");
  const { data, error } = await safe(api(`/v1/findings?${q}`), { total: 0, items: [] as any[] });
  const items = sp.domain ? data.items.filter((f: any) => String(f.ruleId).startsWith(`${sp.domain}-`) || String(f.ruleId).startsWith(`${sp.domain}.`)) : data.items;
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupOps")} › ${t(lang, "findings")}`} title={tr(lang, `판정 목록 (${data.total.toLocaleString()})`, `Findings (${data.total.toLocaleString()})`)} />
      <form className="mb-3 flex gap-2 text-sm">
        <select name="verdict" defaultValue={sp.verdict ?? ""} className="input" aria-label="verdict">
          <option value="">{L(lang, "판정: 전체")}</option>
          {["block", "require_approval", "transform", "alert", "allow"].map((v) => <option key={v}>{v}</option>)}
        </select>
        <input name="agent" defaultValue={sp.agent ?? ""} placeholder={L(lang, "에이전트 (d1-05)")} className="input" />
        <input name="trace" defaultValue={sp.trace ?? ""} placeholder="traceId" className="input mono w-80" />
        <button className="btn btn-primary">{L(lang, "질의")}</button>
      </form>
      {error && <p className="text-sm text-red-600">{error}</p>}
      <div className="card overflow-hidden">
        <table className="grid-table">
          <thead><tr><th>{L(lang, "시각")}</th><th>{L(lang, "판정")}</th><th>{L(lang, "유효")}</th><th>{L(lang, "심각도")}</th><th>{L(lang, "규칙")}</th><th>{L(lang, "에이전트·관문")}</th><th>{L(lang, "신뢰도")}</th><th>trace</th></tr></thead>
          <tbody>
            {items.length === 0 && <tr><td colSpan={8} className="text-muted">{t(lang, "noData")}</td></tr>}
            {items.map((f: any) => (
              <tr key={f.id}>
                <td className="text-xs">{fmtTime(f.occurredAt)}</td>
                <td><VerdictBadge v={f.verdict} /></td>
                <td>{f.effectiveVerdict && f.effectiveVerdict !== f.verdict ? <VerdictBadge v={f.effectiveVerdict} /> : <span className="text-xs text-muted">=</span>}</td>
                <td><SeverityBadge s={f.severity} /></td>
                <td className="mono"><Link className="text-primary" href={`/findings/${f.id}`}>{LX(lang, f.ruleId)}</Link>{f.degraded && <span className="ml-1 text-xs text-red-600">{L(lang, "강등")}</span>}</td>
                <td>{f.agent.id} · {LX(lang, f.gate)}</td>
                <td>{LX(lang, f.confidence)}</td>
                <td className="mono"><Link href={`/findings?trace=${f.traceId}`}>{shortHash(f.traceId)}</Link></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
