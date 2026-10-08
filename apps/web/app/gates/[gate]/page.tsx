// SCR-D02 관문 상세·지연 예산 — 에이전트별 p50/p95/p99·예산 몫·지연 분포, 예산 초과 에이전트 상시 계열 재배치 제안(2인 승인), 비용·SLO 경보(X10).
import Link from "next/link";
import { notFound } from "next/navigation";
import { Banner, Chip, Kpi } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { ApiError, api } from "@/lib/api";
import { nm, t, tr } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { ignoreRelocation, requestRelocation } from "../actions";

const NAMES: Record<string, [string, string]> = { input: ["입력 관문", "Input gate"], tool: ["도구 관문", "Tool gate"], output: ["출력 관문", "Output gate"], offline: ["상시·증적 (경로 밖)", "Continuous · evidence (off-path)"] };
const STATE: Record<string, [string, string, string]> = {
  ok: ["정상", "OK", "var(--verdict-allow)"], near: ["예산 근접", "Near budget", "#e2b007"], over: ["초과", "Over", "var(--verdict-block)"],
  degraded: ["강등", "Degraded", "var(--verdict-block)"], relocated: ["재배치됨", "Relocated", "#9d6105"],
};
const HOURS: [number, string, string][] = [[24, "24시간", "24h"], [168, "7일", "7 days"], [720, "30일", "30 days"]];
const won = (n: number | null | undefined) => (n == null ? "—" : `₩${Math.round(n).toLocaleString("en-US")}`);
const pct = (x: number | null | undefined, d = 0) => (x == null ? "—" : `${(x * 100).toFixed(d)}%`);

export default async function GateDetail({ params, searchParams }: { params: Promise<{ gate: string }>; searchParams: Promise<{ hours?: string; msg?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const { gate } = await params;
  const { hours = "24", msg } = await searchParams;
  if (!NAMES[gate]) notFound();
  let g: any;
  try {
    g = await api(`/v1/gates/${gate}?hours=${Number(hours) || 24}`);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound();
    throw e;
  }
  const write = can(user, "policy.write");
  const near = g.budgetRatio != null && g.budgetRatio >= 0.9;
  const maxBin = Math.max(1, ...g.histogram.map((b: any) => b.count));
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupGates")} › ${t(lang, "gates")} › ${tr(lang, ...NAMES[gate])}`} title={tr(lang, `${NAMES[gate][0]} — 지연 예산 · 에이전트 상세`, `${NAMES[gate][1]} — latency budget · agent detail`)} />
      {msg && <div className="mb-3"><Banner tone={/^(실패|Failed)/.test(msg) ? "danger" : "info"}>{msg}</Banner></div>}
      <div className="mb-3 flex flex-wrap items-center gap-2 text-xs">
        {HOURS.map(([h, ko, en]) => (
          <Link key={h} href={`/gates/${gate}?hours=${h}`} className={`rounded-full border px-3 py-1 ${g.hours === h ? "border-primary bg-primary-soft text-primary" : "border-line"}`}>{tr(lang, ko, en)}</Link>
        ))}
        <span className="ml-auto flex gap-3"><Link className="text-primary" href="/gates">{tr(lang, "← 관문 구성", "← Gates")}</Link><Link className="text-primary" href="/gates/degradation">{tr(lang, "강등 정책·장애 현황 →", "Degradation & failures →")}</Link></span>
      </div>
      <div className="grid grid-cols-5 gap-3" data-testid="gate-kpis">
        <Kpi label={tr(lang, "관문 p95", "Gate p95")} value={`${g.p95Ms}ms`} accent={g.budgetMs ? (g.p95Ms > g.budgetMs ? "var(--verdict-block)" : near ? "#e2b007" : "var(--verdict-allow)") : "var(--sev-info)"}
          sub={g.budgetMs ? tr(lang, `예산 ${g.budgetMs}ms · ${pct(g.budgetRatio)}${near ? " ⚠" : ""}`, `budget ${g.budgetMs}ms · ${pct(g.budgetRatio)}${near ? " ⚠" : ""}`) : tr(lang, "경로 밖 — 시간 제한 없음", "off-path — no time limit")} />
        <Kpi label={tr(lang, "관문 타임아웃", "Gate timeout")} value={g.hardTimeoutMs ? `${g.hardTimeoutMs}ms` : "—"} accent="var(--sev-info)"
          sub={tr(lang, `예산 초과 ${g.overBudget}건 · 강등 ${g.degraded}건`, `over budget ${g.overBudget} · degraded ${g.degraded}`)} />
        <Kpi label={tr(lang, `판정 (${hours === "24" ? "24h" : `${Math.round(g.hours / 24)}d`})`, `Judgments (${hours === "24" ? "24h" : `${Math.round(g.hours / 24)}d`})`)} value={g.records.toLocaleString("en-US")} accent="var(--primary)"
          sub={Object.entries(g.verdicts).map(([k, v]) => `${k} ${v}`).join(" · ") || "—"} />
        <Kpi label={tr(lang, "방어 비용 (월)", "Defense cost (month)")} value={g.cost ? won(g.cost.monthlyProjected) : "—"} accent={g.cost?.ratio >= (g.budgets.alertRatio ?? 0.8) ? "var(--verdict-block)" : "var(--sev-info)"}
          sub={g.cost ? tr(lang, `1k당 ${won(g.cost.per1k)} · 예산 ${pct(g.cost.ratio)}`, `${won(g.cost.per1k)} per 1k · ${pct(g.cost.ratio)} of budget`) : tr(lang, "단가 미설정 — 정책 spec.budgets.costPer1k", "No unit price — policy spec.budgets.costPer1k")} />
        <Kpi label={tr(lang, "오탐률", "False-positive rate")} value={pct(g.fp.rate, 2)} accent={g.fp.rate > g.fp.target ? "var(--verdict-block)" : "var(--verdict-allow)"}
          sub={tr(lang, `목표 ${pct(g.fp.target, 1)} · 확정 오탐 ${g.fp.fp}/${g.fp.judged}`, `target ${pct(g.fp.target, 1)} · confirmed FP ${g.fp.fp}/${g.fp.judged}`)} />
      </div>
      <div className="mt-4 grid grid-cols-[1fr_380px] gap-4">
        <section className="card overflow-hidden text-sm">
          <h2 className="p-3 font-semibold">{tr(lang, "에이전트별 지연 · 예산 몫", "Per-agent latency · budget share")}</h2>
          <table className="grid-table text-xs [&_th]:whitespace-nowrap" data-testid="gate-agents">
            <thead><tr><th>{tr(lang, "에이전트", "Agent")}</th><th>p50</th><th>p95</th><th>p99</th><th>{tr(lang, "타임아웃", "Timeout")}</th><th>{tr(lang, "예산 몫", "Share")}</th>
              <th>{tr(lang, "호출", "Calls")}</th><th>{tr(lang, "타임아웃률", "Timeout rate")}</th><th>{tr(lang, "오탐률", "FP rate")}</th><th>{tr(lang, "연속 초과", "Over streak")}</th><th>{tr(lang, "상태", "State")}</th></tr></thead>
            <tbody>
              {g.agents.length === 0 && <tr><td colSpan={11} className="text-muted">{tr(lang, "바인딩된 에이전트 없음 — 프로파일 적용 후 표시", "No bound agents — apply a profile first")}</td></tr>}
              {g.agents.map((a: any) => {
                const [ko, en, color] = STATE[a.state] ?? STATE.ok;
                return (
                  <tr key={a.id}>
                    <td><Link className="text-primary" href={`/catalog/${a.id}`}>{a.id}</Link> {nm(lang, a)} <span className="text-muted">{a.series} · fail_{a.failMode}</span></td>
                    <td>{a.p50Ms}ms</td><td><b style={{ color: a.p95Ms > a.budgetMs ? "var(--verdict-block)" : undefined }}>{a.p95Ms}ms</b></td><td>{a.p99Ms}ms</td>
                    <td>{a.timeoutMs ? `${a.timeoutMs}ms` : "—"}</td><td>{a.budgetMs}ms</td><td>{a.calls}</td><td>{pct(a.timeoutRate, 1)}</td><td>{pct(a.fpRate, 2)}</td>
                    <td>{a.overDays ? tr(lang, `${a.overDays}일`, `${a.overDays} d`) : "—"}</td>
                    <td className="whitespace-nowrap"><span className="rounded-full px-2 py-0.5 text-white" style={{ background: color }}>{tr(lang, ko, en)}</span></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <p className="p-3 text-xs text-muted">{tr(lang, `병렬 합성 — 관문 p95 ≈ 가장 느린 에이전트 p95 + 합성 오버헤드 ${g.overheadMs}ms. 예산 몫은 합산이 아니라 최댓값이 관문 예산(${g.budgetMs ?? "—"}ms) 안이어야 한다 (몫 합계 ${g.budgetShareSum}ms).`,
            `Parallel composition — gate p95 ≈ slowest agent p95 + composition overhead ${g.overheadMs}ms. Shares are not summed: the largest must fit the gate budget (${g.budgetMs ?? "—"}ms; sum of shares ${g.budgetShareSum}ms).`)}</p>
        </section>
        <aside className="space-y-4">
          <section className="card p-4 text-sm" data-testid="gate-hist">
            <h2 className="mb-2 font-semibold">{tr(lang, "지연 분포", "Latency distribution")}</h2>
            <p className="mb-2 text-xs">p50 {g.p50Ms} · p95 {g.p95Ms} · p99 {g.p99Ms}ms</p>
            <div className="flex h-32 items-end gap-1 pt-2">
              {g.histogram.map((b: any, i: number) => (
                <div key={i} className="flex flex-1 flex-col items-center gap-1" title={`${b.count}`}>
                  <span className="text-[10px] text-muted">{b.count}</span>
                  <div className="w-full rounded-t" style={{ height: `${(b.count / maxBin) * 72}px`, minHeight: b.count ? 2 : 0, background: b.over ? "#e2b007" : "var(--primary)" }} />
                  <span className="text-[10px]">{b.le == null ? `${g.budgetMs ?? ""}+` : `≤${Math.round(b.le)}`}</span>
                </div>
              ))}
            </div>
            {g.budgetMs && <p className="mt-2 text-xs text-muted">{tr(lang, "황색 = 예산 90% 이상 구간", "Amber = bins at or above 90% of budget")}</p>}
          </section>
          <section className="card space-y-2 p-4 text-sm" data-testid="gate-cost">
            <h2 className="font-semibold">{tr(lang, "비용 · SLO 경보 (X10)", "Cost · SLO alerts (X10)")}</h2>
            <dl className="grid grid-cols-[140px_1fr] gap-y-1 text-xs">
              <dt className="text-muted">{tr(lang, "요청 1k 당 비용", "Cost per 1k")}</dt><dd>{won(g.budgets.costPer1k)}</dd>
              <dt className="text-muted">{tr(lang, "월 예산 대비", "Of monthly budget")}</dt><dd>{g.cost?.ratio != null ? `${pct(g.cost.ratio)} (${won(g.cost.monthlyProjected)} / ${won(g.cost.monthlyBudget)})` : "—"}</dd>
              <dt className="text-muted">{tr(lang, "오탐 예산", "FP budget")}</dt><dd>{g.fp.budget.length ? g.fp.budget.map((b: any) => `${b.agent} ${pct(b.consumed)}`).join(" · ") : "—"}</dd>
              <dt className="text-muted">{tr(lang, "경보 규칙", "Alert rule")}</dt><dd>{tr(lang, `p95 예산 몫 ${g.budgets.overStreak}일 연속 초과 · 비용 ${pct(g.budgets.alertRatio)} · 오탐 예산 80%`, `p95 over share ${g.budgets.overStreak} days in a row · cost ${pct(g.budgets.alertRatio)} · FP budget 80%`)}</dd>
            </dl>
            {g.alerts.length ? <ul className="text-xs">{g.alerts.map((a: any, i: number) => <li key={i} style={{ color: a.severity === "high" ? "var(--verdict-block)" : "#9d6105" }}>⚠ {a.text}</li>)}</ul>
              : <p className="text-xs text-muted">{tr(lang, "경보 없음 — 초과 시 알림 센터에 경보(매시 점검)", "No alerts — breaches go to the notification center (hourly check)")}</p>}
            <p className="text-xs text-muted">{tr(lang, "단가·예산은 정책 spec.budgets 에서 설정 →", "Set unit price and budget in policy spec.budgets →")} <Link className="text-primary" href="/policies/edit">{tr(lang, "정책 편집기", "policy editor")}</Link></p>
          </section>
        </aside>
      </div>
      <section className="card mt-4 space-y-3 p-4 text-sm" data-testid="gate-relocation">
        <h2 className="font-semibold">{tr(lang, "재배치 제안 — 예산 초과 에이전트를 상시 계열(C3) 비동기로", "Relocation proposals — move over-budget agents to the continuous series (C3, async)")}</h2>
        {g.placement !== "inline" && <p className="text-xs text-muted">{tr(lang, "경로 밖 관문 — 재배치 대상 아님", "Off-path gate — not applicable")}</p>}
        {g.placement === "inline" && g.suggestions.length === 0 && <p className="text-xs text-muted">{tr(lang, `제안 없음 — 호출 20건 이상이고 p95 가 예산 몫을 넘는 인라인 에이전트가 없다`, "No proposals — no inline agent with ≥ 20 calls has p95 above its share")}</p>}
        {g.suggestions.map((sg: any) => (
          <div key={sg.agent} className="rounded-lg border border-line p-3 text-xs">
            <p><b>{sg.agent}</b> {nm(lang, sg)} — {tr(lang, `p95 ${sg.p95Ms}ms 가 예산 몫 ${sg.budgetMs}ms 초과${sg.overDays ? ` (${sg.overDays}일 연속)` : ""}`, `p95 ${sg.p95Ms}ms exceeds share ${sg.budgetMs}ms${sg.overDays ? ` (${sg.overDays} days in a row)` : ""}`)}
              {sg.sustained && <Chip tone="primary">{tr(lang, "경보 규칙 충족", "alert rule met")}</Chip>}</p>
            <p>{tr(lang, `→ 상시 계열(C3) 비동기 검사로 이동: 관문 p95 ${sg.gateP95Ms} → ${sg.expectedGateP95Ms}ms 예상`, `→ move to continuous (C3) async checks: gate p95 ${sg.gateP95Ms} → ${sg.expectedGateP95Ms}ms expected`)}</p>
            <p className="text-muted">{tr(lang, "대가: 응답 후 판정·표시(차단 불가)", "Trade-off: judged and shown after the response (cannot block)")}</p>
            {sg.pending ? <p className="mt-1">{tr(lang, `승인 대기 ${sg.pending.approval}`, `Awaiting approval ${sg.pending.approval}`)} → <Link className="text-primary" href="/approvals">{tr(lang, "승인함", "Approvals")}</Link></p>
              : sg.ignored ? <p className="mt-1 text-muted">{tr(lang, `무시됨 — ${sg.ignored.by}: ${sg.ignored.reason}`, `Ignored — ${sg.ignored.by}: ${sg.ignored.reason}`)}</p>
              : write && (
                <div className="mt-2 flex flex-wrap gap-2">
                  <form action={requestRelocation} className="flex gap-2"><input type="hidden" name="gate" value={gate} /><input type="hidden" name="agent" value={sg.agent} />
                    <input name="reason" className="input h-7 w-56 text-xs" placeholder={tr(lang, "적용 사유", "Reason")} aria-label="relocate reason" />
                    <button className="btn btn-primary h-7 text-xs">{tr(lang, "제안 적용 요청 (2인 승인)", "Request (two approvals)")}</button></form>
                  <form action={ignoreRelocation} className="flex gap-2"><input type="hidden" name="gate" value={gate} /><input type="hidden" name="agent" value={sg.agent} />
                    <input name="reason" required className="input h-7 w-56 text-xs" placeholder={tr(lang, "무시 사유 (필수)", "Reason (required)")} aria-label="ignore reason" />
                    <button className="btn btn-secondary h-7 text-xs">{tr(lang, "무시", "Ignore")}</button></form>
                </div>
              )}
          </div>
        ))}
        {g.relocated.length > 0 && (
          <div className="text-xs">
            <h3 className="mb-1 font-semibold">{tr(lang, "재배치된 에이전트 (응답 후 판정)", "Relocated agents (judged after response)")}</h3>
            {g.relocated.map((r: any) => (
              <div key={r.agent} className="flex items-center gap-2">
                <Link className="text-primary" href={`/catalog/${r.agent}`}>{r.agent}</Link>
                {r.pending ? <span>{tr(lang, `승인 대기 ${r.pending.approval}`, `Awaiting approval ${r.pending.approval}`)}</span> : write && (
                  <form action={requestRelocation} className="flex gap-2"><input type="hidden" name="gate" value={gate} /><input type="hidden" name="agent" value={r.agent} /><input type="hidden" name="restore" value="1" />
                    <button className="btn btn-secondary h-6 text-xs">{tr(lang, "인라인 복귀 요청", "Request restore to inline")}</button></form>
                )}
              </div>
            ))}
          </div>
        )}
        <p className="text-xs text-muted">{tr(lang, "적용·복귀 = 정책 relocated 변경 → 2인 승인 → 새 정책 버전(10초 안 반영). 무시는 사유와 함께 원장에 기록.", "Apply/restore = change policy `relocated` → two approvals → new policy version (live within 10 s). Ignoring records the reason in the ledger.")}</p>
      </section>
    </>
  );
}
