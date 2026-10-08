// SCR-Q02 레드팀 실행 승인·대상 범위 — 시나리오 → 대상(등록부) → 격리 → 조직 승인(2인) → 실행.
import Link from "next/link";
import { Banner } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { t, tr, LX } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { requestRedteam } from "@/app/instant/preview-actions";

import { L } from "@/lib/i18n";

export default async function RedteamRun({ searchParams }: { searchParams: Promise<{ msg?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const { msg } = await searchParams;
  const [{ data: ag }, { data: sb }] = await Promise.all([safe(api("/v1/agents"), { items: [] as any[] }), safe(api("/v1/sandbox"), null as any)]);
  const builtin = ag.items.filter((a: any) => a.origin === "builtin" && a.status !== "stopped");
  const byDomain: Record<string, any[]> = {};
  for (const a of builtin) (byDomain[a.itemId.startsWith("D") ? a.itemId.split("-")[0] : "X"] ??= []).push(a);
  return (
    <>
      <PageHeader crumb={`${t(lang, "redteam")} › ${t(lang, "redteamRun")}`} title={tr(lang, "레드팀 실행 — 범위·격리·승인", "Red team run — scope, isolation, approval")} />
      {msg && <div className="mb-3"><Banner tone={msg.startsWith(L(lang, "실패")) ? "danger" : "info"}>{msg} {msg.includes("apr_") && <Link className="text-primary" href="/approvals">{L(lang, "승인함")}</Link>}</Banner></div>}
      <ol className="mb-3 flex gap-2 text-xs">{["① 시나리오", "② 대상 범위", "③ 격리·자산", "④ 조직 승인(2인)", "⑤ 실행"].map((s) => <li key={s} className="rounded-full border border-line bg-panel px-3 py-1">{L(lang, s)}</li>)}</ol>
      <form action={requestRedteam} className="grid grid-cols-[1fr_340px] gap-4">
        <section className="card p-4 text-sm">
          <h2 className="mb-2 font-semibold">② {tr(lang, "대상 — 등록부의 에이전트만 (비우면 전체)", "Targets — registered agents only (empty = all)")}</h2>
          <div className="grid grid-cols-4 gap-3 text-xs">{Object.entries(byDomain).map(([d, list]) => (
            <fieldset key={d}><legend className="font-semibold">{d}</legend>{list.map((a: any) => (
              <label key={a.id} className="flex items-center gap-1"><input type="checkbox" name="agents" value={a.id} />{a.id}</label>
            ))}</fieldset>
          ))}</div>
        </section>
        <section className="card h-fit space-y-2 p-4 text-sm">
          <h2 className="font-semibold">① {tr(lang, "시나리오", "Scenario")}</h2>
          <select name="scenario" className="input w-full" defaultValue="internal-corpus" aria-label={tr(lang, "시나리오", "Scenario")}><option value="internal-corpus">{L(lang, "내부 공격 코퍼스 재생 (회귀 기준선 비교)")}</option></select>
          <h2 className="pt-2 font-semibold">③ {tr(lang, "격리·자산", "Isolation & assets")}</h2>
          <p className="text-xs">{L(lang, "PRD: L3 고정. 이 설치: L3 런타임 없음 → 외부 자산 미대상, 내부 코퍼스만 (현재 최고 격리 ")}{LX(lang, sb?.maxLevel ?? "—")})</p>
          <h2 className="pt-2 font-semibold">④ {tr(lang, "조직 승인", "Approval")}</h2>
          <input name="reason" required placeholder={L(lang, "실행 사유·변경 번호")} className="input w-full" aria-label="reason" />
          <button className="btn btn-primary w-full justify-center" disabled={!can(user, "redteam")} title={can(user, "redteam") ? "" : L(lang, "레드팀 역할 필요")}>{L(lang, "승인 요청")}</button>
          <p className="text-xs text-muted">{L(lang, "2인 승인 완료 시 실행되고 결과는 원장·회귀 기준선에 남는다 (이중 용도 통제 §13.1).")}</p>
        </section>
      </form>
    </>
  );
}
