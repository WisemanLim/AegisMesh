// SCR-N02 통제-규제 매핑·보고서.
import Link from "next/link";
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { t, tr, LX } from "@/lib/i18n";
import { prefs } from "@/lib/session";

import { L } from "@/lib/i18n";

const TONE: Record<string, string> = { covered: "var(--verdict-allow)", partial: "var(--verdict-approval)", missing: "var(--verdict-block)" };

export default async function Reports({ searchParams }: { searchParams: Promise<{ fw?: string }> }) {
  const { lang } = await prefs();
  const { fw = "owasp-llm-2026" } = await searchParams;
  const [list, rep] = await Promise.all([safe(api(`/v1/reports?lang=${lang}`), { items: [] as any[] }), safe(api(`/v1/reports/${fw}?lang=${lang}`), null as any)]);
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupGov")} › ${t(lang, "reports")}`} title={tr(lang, "통제-규제 매핑 보고서", "Control-to-regulation reports")}
        actions={<a className="btn btn-secondary" href={`/reports/export?fw=${fw}`}>{L(lang, "Markdown 받기")}</a>} />
      <div className="mb-3 flex flex-wrap gap-2 text-sm">
        {list.data.items.map((f: any) => <Link key={f.id} href={`/reports?fw=${f.id}`} className={`rounded-full px-3 py-1 ${f.id === fw ? "bg-primary text-white" : "border border-line bg-panel"}`}>{LX(lang, f.title)}</Link>)}
      </div>
      {rep.data && (
        <>
          <div className="mb-3 flex gap-3 text-sm">
            <Chip>{L(lang, "충족 ")}{LX(lang, rep.data.summary.covered)}</Chip><Chip>{L(lang, "부분 ")}{LX(lang, rep.data.summary.partial)}</Chip><Chip>{L(lang, "누락 ")}{LX(lang, rep.data.summary.missing)}</Chip>
            <Chip tone="primary">{L(lang, "원장 ")}{rep.data.evidence.ledgerOk ? L(lang, "무결성 ✓") : "✗"} · {rep.data.evidence.records.toLocaleString()}{L(lang, "건")}</Chip>
          </div>
          <div className="card overflow-hidden">
            <table className="grid-table">
              <thead><tr><th>{L(lang, "통제")}</th><th>{L(lang, "제목")}</th><th>{L(lang, "상태")}</th><th>{L(lang, "구현 항목")}</th><th>{L(lang, "플랫폼 통제")}</th><th>{L(lang, "30일 비허용 판정")}</th></tr></thead>
              <tbody>
                {rep.data.controls.map((c: any) => (
                  <tr key={c.id}>
                    <td className="mono">{c.id}</td><td>{LX(lang, c.title)}</td>
                    <td><span className="font-semibold" style={{ color: TONE[c.status] }}>{LX(lang, c.status)}</span></td>
                    <td className="text-xs">{c.implemented.join(", ") || "—"}{c.missing.length > 0 && <div className="text-red-600">{L(lang, "누락 ")}{c.missing.join(", ")}</div>}</td>
                    <td className="text-xs">{Object.entries(c.platform).map(([k, v]) => `${k}${v ? "✓" : "✗"}`).join(" ") || "—"}</td>
                    <td>{LX(lang, c.findings30d)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-3"><Banner tone="info">{LX(lang, rep.data.disclaimer)}</Banner></div>
        </>
      )}
    </>
  );
}
