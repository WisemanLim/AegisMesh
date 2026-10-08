// SCR-D01 관문 구성 · SCR-D02 관문 상세·지연 예산 · SCR-D06 강등 정책·장애 현황.
import Link from "next/link";
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime, shortHash } from "@/lib/format";
import { t, tr, nm, LX } from "@/lib/i18n";
import { prefs } from "@/lib/session";

import { L } from "@/lib/i18n";

const GATES = [["input", "입력 (C1)"], ["tool", "도구 (C2)"], ["output", "출력 (C1·C3)"], ["offline", "상시·증적 (C3·C4)"]];

export default async function Gates({ searchParams }: { searchParams: Promise<{ hours?: string }> }) {
  const { lang } = await prefs();
  const { hours = "24" } = await searchParams;
  const { data: g, error } = await safe(api(`/v1/gates?hours=${Number(hours) || 24}`), null as any);
  if (!g) return <><PageHeader crumb={t(lang, "groupGates")} title={tr(lang, "관문 구성", "Gates")} /><Banner tone="danger">{error}</Banner></>;
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupGates")} › ${t(lang, "gates")}`} title={tr(lang, `관문 구성 · 지연 예산 · 강등 현황 (${g.tenant === "*" ? "전체 테넌트" : g.tenant}, ${g.hours}시간)`, `Gates · latency budget · degradation (${g.tenant === "*" ? "all tenants" : g.tenant}, ${g.hours}h)`)} />
      <p className="mb-2 flex gap-4 text-xs"><Link className="text-primary" href="/gates/input">{tr(lang, "관문 상세·지연 예산 →", "Gate detail · latency budget →")}</Link><Link className="text-primary" href="/gates/degradation">{tr(lang, "강등 정책·장애 현황 →", "Degradation & failures →")}</Link></p>
      <div className="mb-3 flex flex-wrap gap-2 text-xs">
        {g.applications.length === 0 ? <Banner tone="warn">{L(lang, "적용된 프로파일 없음 — ")}<Link className="text-primary" href="/instant">{L(lang, "즉시 사용")}</Link>{L(lang, "에서 적용하면 관문에 바인딩된다.")}</Banner>
          : g.applications.map((a: any) => <Chip key={a.id} tone="primary">{LX(lang, a.tenant)} · {LX(lang, a.profile)} → {LX(lang, a.target)} ({LX(lang, a.stage)})</Chip>)}
      </div>
      <div className="grid grid-cols-2 gap-4">
        {GATES.map(([id, label]) => {
          const x = g.gates[id];
          const over = x.budgetMs && x.p95Ms > x.budgetMs;
          return (
            <section key={id} className="card p-4 text-sm" data-testid={`gate-${id}`}>
              <div className="mb-2 flex items-center justify-between">
                <h2 className="font-semibold"><Link className="text-primary" href={`/gates/${id}`}>{L(lang, label)}</Link> <span className="text-xs font-normal text-muted">{LX(lang, x.placement)}</span></h2>
                <span className="text-xs">p95 <b style={{ color: over ? "var(--verdict-block)" : undefined }}>{LX(lang, x.p95Ms)}ms</b>{L(lang, " / 예산 ")}{LX(lang, x.budgetMs ?? "—")}{L(lang, "ms · 하드 타임아웃 ")}{LX(lang, x.hardTimeoutMs ?? "—")}ms</span>
              </div>
              <p className="mb-2 text-xs text-muted">{L(lang, "병렬 분배 · 합성 = ")}{LX(lang, x.composition)}{L(lang, " · 기록 ")}{LX(lang, x.records)}{L(lang, " · 예산 초과 ")}{LX(lang, x.overBudget)}{L(lang, " · 강등 ")}{LX(lang, x.degraded)}</p>
              <table className="grid-table text-xs">
                <thead><tr><th>{L(lang, "에이전트")}</th><th>failMode</th><th>{L(lang, "p95 / 몫")}</th><th>{L(lang, "호출")}</th><th>{L(lang, "강등")}</th><th>{L(lang, "상태")}</th></tr></thead>
                <tbody>
                  {x.agents.length === 0 && <tr><td colSpan={6} className="text-muted">{L(lang, "바인딩 없음")}</td></tr>}
                  {x.agents.map((a: any) => (
                    <tr key={a.id}>
                      <td><Link className="text-primary" href={`/catalog/${a.id}`}>{a.id}</Link> {nm(lang, a)}</td>
                      <td><Chip tone={a.failMode === "closed" ? "primary" : undefined}>{a.failMode === "closed" ? L(lang, "차단") : L(lang, "통과")}</Chip></td>
                      <td>{LX(lang, a.p95Ms)}ms / {LX(lang, a.budgetMs)}ms{a.relocate && <span title={L(lang, "예산 초과 — 상시 계열(비동기) 재배치 제안")} style={{ color: "var(--verdict-block)" }}>{L(lang, " ⚠ 재배치")}</span>}</td>
                      <td>{LX(lang, a.calls)}</td><td>{LX(lang, a.degraded)}</td><td>{LX(lang, a.status)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          );
        })}
      </div>
      <div className="mt-4 grid grid-cols-[1fr_360px] gap-4">
        <section className="card p-4 text-sm">
          <h2 className="mb-2 font-semibold">{L(lang, "강등 기록 (최근 ")}{g.degradedEvents.length}{L(lang, "건 — 모두 증적에 남음)")}</h2>
          <table className="grid-table text-xs"><thead><tr><th>seq</th><th>{L(lang, "시각")}</th><th>{L(lang, "관문")}</th><th>{L(lang, "강등 에이전트")}</th><th>{L(lang, "합성 판정")}</th><th>trace</th></tr></thead>
            <tbody>
              {g.degradedEvents.length === 0 && <tr><td colSpan={6} className="text-muted">{L(lang, "강등 없음")}</td></tr>}
              {g.degradedEvents.map((e: any) => (
                <tr key={e.seq}><td>{e.seq}</td><td>{fmtTime(e.at)}</td><td>{LX(lang, e.gate)}</td><td>{e.agents.join(", ")}</td><td>{LX(lang, e.verdict)}</td>
                  <td className="mono"><Link className="text-primary" href={`/findings?trace=${e.traceId}`}>{shortHash(e.traceId)}</Link></td></tr>
              ))}
            </tbody></table>
        </section>
        <section className="card space-y-2 p-4 text-sm">
          <h2 className="font-semibold">{L(lang, "실패 모드 기본 동작")}</h2>
          <ul className="text-xs">{Object.entries(g.failModes).map(([k, v]) => <li key={k}><b>{k}</b>: {L(lang, String(v))}</li>)}</ul>
          <p className="text-xs text-muted">{L(lang, "하드 타임아웃 = 관문 p95 예산 × ")}{LX(lang, g.timeoutFactor)}</p>
          <h2 className="pt-2 font-semibold">{L(lang, "경보 전용 강등 (alert_only) ")}{g.alertOnly.length}</h2>
          <ul className="text-xs">{g.alertOnly.length === 0 ? <li className="text-muted">{L(lang, "없음")}</li> : g.alertOnly.map((a: any) => <li key={a.id}>{a.id} {LX(lang, a.nameKo)} ({LX(lang, a.gate)})</li>)}</ul>
          <p className="text-xs text-muted">{LX(lang, g.recovery)}</p>
          <p className="text-xs">{L(lang, "상시 계열(C3) 발견 → 격리 목록 → 인라인 관문이 즉시 차단: ")}<Link className="text-primary" href="/scan">{L(lang, "상시 점검·격리")}</Link></p>
        </section>
      </div>
    </>
  );
}
