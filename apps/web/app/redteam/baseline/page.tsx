// SCR-Q03 회귀 기준선·배포 게이트·누락 검증 — 탐지율 < 기준선이면 배포 차단, 도식 80 항목 누락 검증(verify_coverage).
import Link from "next/link";
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { t, tr, LX } from "@/lib/i18n";
import { prefs } from "@/lib/session";

import { L } from "@/lib/i18n";

export default async function Baseline() {
  const { lang } = await prefs();
  const [{ data: obs }, { data: cov }, { data: dg }] = await Promise.all([safe(api("/v1/observability"), null as any), safe(api("/v1/coverage"), null as any),
    safe(api("/v1/compliance/deploy-gate"), null as any)]);
  const cards: string[] = (dg?.reasons ?? []).filter((r: any) => r.kind === "card").map((r: any) => r.subject);   // SCR-N07 카드 미갱신 = 배포 차단
  const fp = obs?.slo?.fp ?? [];
  const regressions: string[] = obs?.slo?.regressions ?? [];
  const missing: string[] = (cov?.strict?.failures ?? []).map((f: any) => f.id);
  const gateOk = regressions.length === 0 && missing.length === 0 && cards.length === 0;
  return (
    <>
      <PageHeader crumb={`${t(lang, "redteam")} › ${t(lang, "baseline")}`} title={tr(lang, "회귀 기준선 · 배포 게이트 · 누락 검증", "Regression baseline · deploy gate · coverage")} />
      <div className="mb-3"><Banner tone={gateOk ? "info" : "danger"}>{gateOk ? L(lang, "배포 게이트 통과 — 회귀 0 · 엄격 누락 0") : L(lang, "배포 차단 — 회귀 {0} · 누락 {1}", regressions.join(", ") || 0, missing.join(", ") || 0)}
        {cards.length > 0 && <> · <Link className="underline" href="/compliance/cards">{tr(lang, `카드 갱신 필요 ${cards.join(", ")} (MSG-021)`, `cards need refresh ${cards.join(", ")} (MSG-021)`)}</Link></>}</Banner></div>
      <div className="grid grid-cols-[1fr_380px] gap-4">
        <section className="card overflow-hidden text-sm" data-testid="baseline">
          <h2 className="p-3 font-semibold">{tr(lang, `에이전트별 탐지율 vs 기준선 (레드팀 ${obs?.slo?.redteamAt ? fmtTime(obs.slo.redteamAt) : "기록 없음"})`, "Detection vs baseline")}</h2>
          <table className="grid-table text-xs"><thead><tr><th>{L(lang, "에이전트")}</th><th>{L(lang, "탐지율")}</th><th>{L(lang, "기준선")}</th><th>{L(lang, "오탐")}</th><th>{L(lang, "게이트")}</th></tr></thead>
            <tbody>{fp.length === 0 ? <tr><td colSpan={5} className="text-muted">{L(lang, "레드팀 캠페인 실행 후 표시")}</td></tr> : fp.map((x: any) => (
              <tr key={x.agent}><td>{LX(lang, x.agent)}</td><td>{LX(lang, x.detectionRate)}</td><td>{LX(lang, x.baseline)}</td><td>{(x.fpRate * 100).toFixed(2)}%</td>
                <td>{x.regression ? <b style={{ color: "var(--verdict-block)" }}>{L(lang, "회귀 — 차단")}</b> : L(lang, "통과")}</td></tr>
            ))}</tbody></table>
        </section>
        <section className="card h-fit space-y-2 p-4 text-sm">
          <h2 className="font-semibold">{tr(lang, "누락 검증 (CI · verify_coverage)", "Coverage gate (CI)")}</h2>
          {cov ? (<>
            <p className="text-xs" data-testid="coverage">{L(lang, "전체 ")}<b>{LX(lang, cov.implemented)}/{cov.total}</b>{L(lang, " · 엄격(P0·단계 범위) ")}<b>{LX(lang, cov.strict.implemented)}/{cov.strict.total}</b></p>
            <div className="flex flex-wrap gap-1">{missing.map((m) => <Chip key={m}>{m}</Chip>)}</div>
          </>) : <p className="text-xs text-muted">—</p>}
          <p className="text-xs text-muted">CI: <code className="mono">make coverage</code> · <code className="mono">python -m aegis eval --all</code>{L(lang, " (기준선 회귀 시 실패)")}</p>
        </section>
      </div>
    </>
  );
}
