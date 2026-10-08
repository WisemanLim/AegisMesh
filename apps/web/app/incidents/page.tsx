// SCR-O03 사건 목록·상관 분석.
import Link from "next/link";
import { Chip, SeverityBadge } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { t, tr, LX } from "@/lib/i18n";
import { prefs } from "@/lib/session";

import { L } from "@/lib/i18n";

export default async function Incidents({ searchParams }: { searchParams: Promise<{ status?: string }> }) {
  const { lang } = await prefs();
  const { status = "open" } = await searchParams;
  const { data } = await safe(api(`/v1/incidents?status=${status}`), { items: [] as any[] });
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupOps")} › ${t(lang, "incidents")}`} title={tr(lang, "사건 목록 — 상관 분석", "Incidents — correlation")} />
      <div className="mb-3 flex gap-2 text-sm">
        {["open", "closed"].map((s) => <Link key={s} href={`/incidents?status=${s}`} className={`rounded-full px-3 py-1 ${s === status ? "bg-primary text-white" : "border border-line bg-panel"}`}>{s}</Link>)}
      </div>
      <div className="card overflow-hidden">
        <table className="grid-table">
          <thead><tr><th>{L(lang, "사건")}</th><th>{L(lang, "심각도")}</th><th>{L(lang, "도메인")}</th><th>{L(lang, "판정·추적")}</th><th>{L(lang, "에이전트")}</th><th>{L(lang, "봉쇄")}</th><th>{L(lang, "갱신")}</th></tr></thead>
          <tbody>
            {data.items.length === 0 && <tr><td colSpan={7} className="text-muted">{t(lang, "noData")}</td></tr>}
            {data.items.map((i: any) => (
              <tr key={i.id}>
                <td><Link className="text-primary" href={`/incidents/${i.id}`}>{LX(lang, i.title)}</Link><div className="mono text-xs text-muted">{i.id}</div></td>
                <td><SeverityBadge s={i.severity} /></td><td><Chip>{LX(lang, i.domain)}</Chip></td>
                <td>{LX(lang, i.findingCount)}{L(lang, "건 · trace ")}{LX(lang, i.traceCount)}</td><td className="text-xs">{i.agents.join(", ")}</td>
                <td>{i.contained ? "✓" : "—"}</td><td className="text-xs">{fmtTime(i.updatedAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
