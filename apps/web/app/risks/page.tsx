// SCR-N03 위험 등록부.
import { Banner } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { addRisk } from "@/lib/actions";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { t, tr, LX } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";

import { L } from "@/lib/i18n";

export default async function Risks({ searchParams }: { searchParams: Promise<{ msg?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const { msg } = await searchParams;
  const { data } = await safe(api("/v1/risks"), { items: [] as any[] });
  const ro = !can(user, "governance");
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupGov")} › ${t(lang, "risks")}`} title={tr(lang, "위험 등록부", "Risk register")} />
      {msg && <div className="mb-3"><Banner tone={msg.startsWith(L(lang, "실패")) ? "danger" : "info"}>{L(lang, msg)}</Banner></div>}
      <div className="grid grid-cols-[1fr_340px] gap-4">
        <div className="card overflow-hidden">
          <table className="grid-table">
            <thead><tr><th>ID</th><th>{L(lang, "위험")}</th><th>AIVSS</th><th>{L(lang, "처리")}</th><th>{L(lang, "책임자")}</th><th>{L(lang, "기한")}</th></tr></thead>
            <tbody>
              {data.items.length === 0 && <tr><td colSpan={6} className="text-muted">{t(lang, "noData")}</td></tr>}
              {data.items.map((r: any) => (
                <tr key={r.id}><td className="mono">{r.id}</td><td>{LX(lang, r.title)}</td><td>{LX(lang, r.score ?? "—")}</td><td>{LX(lang, r.decision)}</td><td>{LX(lang, r.owner ?? "—")}</td><td className="text-xs">{fmtTime(r.dueAt)}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
        <form action={addRisk} className="card space-y-2 p-4 text-sm">
          <h2 className="font-semibold">{L(lang, "위험 등록")}</h2>
          <input name="title" required placeholder={L(lang, "위험")} className="input w-full" aria-label="title" />
          <input name="score" type="number" step="0.1" min="0" max="10" placeholder={L(lang, "AIVSS 점수")} className="input w-full" aria-label="score" />
          <select name="decision" className="input w-full" aria-label="decision" defaultValue="mitigate">
            {["mitigate", "accept", "transfer", "avoid", "open"].map((d) => <option key={d}>{d}</option>)}
          </select>
          <input name="owner" placeholder={L(lang, "책임자")} className="input w-full" aria-label="owner" />
          <input name="dueAt" type="date" className="input w-full" aria-label="due" />
          <button className="btn btn-primary w-full justify-center" disabled={ro} title={ro ? t(lang, "readOnly") : undefined}>{L(lang, "결정 기록(원장)")}</button>
          <p className="text-xs text-muted">{L(lang, "수용(accept)은 책임자·기한 필수 (MSG-003).")}</p>
        </form>
      </div>
    </>
  );
}
