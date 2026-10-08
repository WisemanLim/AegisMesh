// SCR-Q01 레드팀 캠페인 — 내부 공격 코퍼스 재생, 회귀 기준선, 언어별 성능 분해.
import { Banner } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { runRedteam } from "@/lib/actions";
import { api, safe } from "@/lib/api";
import { t, tr, LX } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";

import { L } from "@/lib/i18n";

export default async function Redteam({ searchParams }: { searchParams: Promise<{ msg?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const { msg } = await searchParams;
  const { data } = await safe(api("/v1/redteam/campaigns"), { items: [] as any[] });
  const ro = !can(user, "redteam");
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupOpsRt")} › ${t(lang, "redteam")}`} title={tr(lang, "레드팀 캠페인", "Red team campaigns")}
        actions={<form action={runRedteam}><button className="btn btn-primary" disabled={ro} title={ro ? t(lang, "readOnly") : undefined}>{L(lang, "캠페인 실행")}</button></form>} />
      {msg && <div className="mb-3"><Banner tone={msg.startsWith(L(lang, "실패")) ? "danger" : "info"}>{L(lang, msg)}</Banner></div>}
      <div className="mb-3"><Banner tone="warn">{L(lang, "대상은 플랫폼 자신의 에이전트(내부 공격 코퍼스)뿐이다. 외부 자산 대상 실행은 사전 등록·조직 승인 후에만 (이중 용도 통제 §13.1).")}</Banner></div>
      <div className="card overflow-hidden">
        <table className="grid-table">
          <thead><tr><th>{L(lang, "원장 seq")}</th><th>{L(lang, "시각")}</th><th>{L(lang, "실행 주체")}</th><th>{L(lang, "에이전트")}</th><th>{L(lang, "회귀")}</th><th>{L(lang, "언어별 탐지율·오탐률")}</th><th>{L(lang, "소요")}</th></tr></thead>
          <tbody>
            {data.items.length === 0 && <tr><td colSpan={7} className="text-muted">{t(lang, "noData")}</td></tr>}
            {data.items.map((c: any) => (
              <tr key={c.seq}><td className="mono">{c.seq}</td><td className="text-xs">{LX(lang, c.at)}</td><td>{LX(lang, c.by)}</td><td>{LX(lang, c.agents)}</td>
                <td style={{ color: c.regressions?.length ? "var(--verdict-block)" : undefined }}>{c.regressions?.length ? c.regressions.map((r: any) => r.agent).join(", ") : "0"}</td>
                <td className="text-xs">{(c.fairness ?? []).map((g: any) => `${g.group}: tpr ${g.tpr} · fpr ${g.fpr} (n ${g.n})`).join(" / ")}</td>
                <td>{LX(lang, c.durationMs)}ms</td></tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
