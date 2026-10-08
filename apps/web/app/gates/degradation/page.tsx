// SCR-D06 강등 정책·장애 현황 — 현재 강등(closed/open)·경보 전용·매니페스트 failMode·실패 모드별 기본 동작(§8.6)·자동 강등 규칙·강등 이력(원장).
import Link from "next/link";
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { nm, t, tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";

const COMP: Record<string, [string, string, string]> = {
  inline: ["인라인 타임아웃", "Inline timeout", "C1·C2 block · C3·C4 pass + degradation evidence"],
  pdp: ["정책 결정점 장애", "Policy decision point failure", "Judge locally with the last policy snapshot (gate cache)"],
  ledger: ["증적 원장 장애", "Evidence ledger failure", "Keep serving · local queue (buffer) then batch write · allow-verdict sampling when saturated"],
  registry: ["레지스트리 장애", "Registry failure", "Keep existing bindings · stop new registrations only"],
  sandbox: ["샌드박스 고갈", "Sandbox exhaustion", "Queue → reject after the wait limit · never lower isolation"],
};
const pct = (x: number | null | undefined) => (x == null ? "—" : `${Math.round(x * 100)}%`);

function nowText(lang: "ko" | "en", c: any): string {
  const m = c.metrics ?? {};
  switch (c.id) {
    case "inline": return m.degraded ? tr(lang, `강등 ${m.degraded}건`, `${m.degraded} degraded`) : tr(lang, "정상", "OK");
    case "pdp": return m.policy ? tr(lang, `정상 · ${m.policy}`, `OK · ${m.policy}`) : tr(lang, "내장 기본 정책", "built-in default policy");
    case "ledger": return m.sampling ? tr(lang, "표본 적재(강등) 중", "sampling (degraded)") : tr(lang, `정상 · 실패 ${m.failed} · 버림 ${m.dropped}`, `OK · failed ${m.failed} · dropped ${m.dropped}`);
    case "sandbox": return m.l1 ? tr(lang, `L1 대기 ${m.queued} · 거부 ${m.rejected}`, `L1 queued ${m.queued} · rejected ${m.rejected}`) : tr(lang, "L1 런타임 없음 — L1 에이전트 보류", "No L1 runtime — L1 agents held");
    default: return tr(lang, "정상", "OK");
  }
}

export default async function Degradation({ searchParams }: { searchParams: Promise<{ gate?: string }> }) {
  const { lang } = await prefs();
  const { gate = "" } = await searchParams;
  const d = await api("/v1/gates/degradation?days=7");
  const modes = d.failModes.filter((a: any) => !gate || a.gate === gate);
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupGates")} › ${tr(lang, "강등 정책", "Degradation policy")}`} title={tr(lang, "강등 정책 · 장애 현황", "Degradation policy · failure status")} />
      {d.current.length > 0 && (
        <div className="mb-3 space-y-1" data-testid="degrade-banner">
          {d.current.map((c: any) => (
            <Banner key={c.gate + c.agent} tone="danger">
              ⛔ {tr(lang, `강등 — ${c.gate} 관문 ${c.agent} 타임아웃 → fail-${c.failMode} ${c.failMode === "closed" ? "로 응답 차단 중" : "— 통과 + 경보"} (${fmtTime(c.start)}~) · 증적 기록됨 · 해소 시 자동 해제`,
                `Degraded — ${c.gate} gate ${c.agent} timeout → fail-${c.failMode} ${c.failMode === "closed" ? "blocking responses" : "— pass + alert"} (since ${fmtTime(c.start)}) · recorded in evidence · clears automatically when resolved`)}
            </Banner>
          ))}
        </div>
      )}
      <div className="grid grid-cols-2 gap-4">
        <section className="card p-4 text-sm" data-testid="degrade-current">
          <h2 className="mb-2 font-semibold">{tr(lang, `현재 강등 (최근 ${d.activeWindowMin}분)`, `Current degradation (last ${d.activeWindowMin} min)`)}</h2>
          {d.current.length === 0 ? <p className="text-xs text-muted">{tr(lang, "없음 — 모든 관문 정상", "None — all gates healthy")}</p> : (
            <ul className="space-y-1 text-xs">{d.current.map((c: any) => (
              <li key={c.gate + c.agent} className="flex items-center gap-2">
                <span className="rounded-full px-2 py-0.5 text-white" style={{ background: c.failMode === "closed" ? "var(--verdict-block)" : "#e07b00" }}>{c.failMode}</span>
                <Link className="text-primary" href={`/gates/${c.gate}`}>{c.agent}</Link> {nm(lang, c)} · {c.gate} · {fmtTime(c.start)}
                {c.timeoutRate != null && ` · ${tr(lang, "타임아웃", "timeout")} ${pct(c.timeoutRate)}`} · {tr(lang, c.failMode === "closed" ? "차단 중" : "통과+경보", c.failMode === "closed" ? "blocking" : "pass+alert")} · {c.count}{tr(lang, "건", "")}
              </li>
            ))}</ul>
          )}
          <h2 className="mb-2 mt-4 font-semibold">{tr(lang, "경보 전용 · 오탐 예산", "Alert-only · FP budget")}</h2>
          {d.alertOnly.length === 0 ? <p className="text-xs text-muted">{tr(lang, "없음", "None")}</p> : (
            <ul className="space-y-1 text-xs" data-testid="degrade-alertonly">{d.alertOnly.map((a: any) => (
              <li key={a.agent}>
                <Link className="text-primary" href={`/catalog/${a.agent}`}>{a.agent}</Link> {nm(lang, a)} · {a.gate} ·{" "}
                {a.agentStatus === "alert_only" ? <b style={{ color: "#9d6105" }}>{tr(lang, "경보 전용(차단 안 함)", "alert-only (no blocking)")}</b> : tr(lang, `오탐 예산 ${pct(a.consumed)}`, `FP budget ${pct(a.consumed)}`)}
                {a.recovery && ` · ${tr(lang, `복귀 조건 ${a.recovery.met ? "충족" : "대기"} (${fmtTime(a.recovery.after)} 이후 · 7일 ${pct(a.recovery.weekFpRate)})`, `recovery ${a.recovery.met ? "met" : "pending"} (after ${fmtTime(a.recovery.after)} · 7-day ${pct(a.recovery.weekFpRate)})`)}`}
              </li>
            ))}</ul>
          )}
        </section>
        <section className="card p-4 text-sm" data-testid="degrade-components">
          <h2 className="mb-2 font-semibold">{tr(lang, "실패 모드별 기본 동작 (§8.6)", "Default behavior by failure mode (§8.6)")}</h2>
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "실패", "Failure")}</th><th>{tr(lang, "기본 동작", "Default")}</th><th>{tr(lang, "현재", "Now")}</th></tr></thead>
            <tbody>{d.components.map((c: any) => (
              <tr key={c.id}><td>{tr(lang, COMP[c.id][0], COMP[c.id][1])}</td><td>{tr(lang, c.default, COMP[c.id][2])}</td>
                <td style={{ color: c.ok ? "var(--verdict-allow)" : "var(--verdict-block)" }}>{nowText(lang, c)}</td></tr>
            ))}</tbody></table>
          <p className="mt-2 text-xs font-semibold">{tr(lang, "격리 등급을 낮추는 강등은 어떤 경우에도 없음 (MSG-006)", "Degradation never lowers the isolation level (MSG-006)")}</p>
          <h2 className="mb-2 mt-4 font-semibold">{tr(lang, "오탐 예산 자동 강등 규칙", "FP-budget automatic degradation rules")}</h2>
          <dl className="grid grid-cols-[160px_1fr] gap-y-1 text-xs">
            <dt className="text-muted">{tr(lang, "경보", "Alert")}</dt><dd>{tr(lang, `예산 ${pct(d.autoRules.warnAt)}`, `budget ${pct(d.autoRules.warnAt)}`)}</dd>
            <dt className="text-muted">{tr(lang, "자동 강등", "Auto-degrade")}</dt><dd>{tr(lang, `${pct(d.autoRules.demoteAt)} 초과 → 경보 전용`, `over ${pct(d.autoRules.demoteAt)} → alert-only`)}</dd>
            <dt className="text-muted">{tr(lang, "예산", "Budget")}</dt><dd>{tr(lang, `max(${d.autoRules.budgetMin}, 판정 × ${d.autoRules.recoverRate * 100}%)/일`, `max(${d.autoRules.budgetMin}, judged × ${d.autoRules.recoverRate * 100}%)/day`)}</dd>
            <dt className="text-muted">{tr(lang, "복귀", "Recovery")}</dt><dd>{tr(lang, `${d.autoRules.recoverDays}일 오탐률 ≤ ${d.autoRules.recoverRate * 100}%`, `${d.autoRules.recoverDays}-day FP rate ≤ ${d.autoRules.recoverRate * 100}%`)}</dd>
            <dt className="text-muted">{tr(lang, "복귀 확정", "Recovery by")}</dt><dd>{tr(lang, "자동(worker) — 원장 quality fp_budget_restored", "Automatic (worker) — ledger quality fp_budget_restored")}</dd>
          </dl>
        </section>
      </div>
      <section className="card mt-4 overflow-hidden text-sm" data-testid="degrade-failmodes">
        <div className="flex items-center gap-2 p-3">
          <h2 className="font-semibold">{tr(lang, "에이전트별 failMode (매니페스트)", "Per-agent failMode (manifest)")}</h2>
          <span className="ml-auto flex gap-1 text-xs">{["", "input", "tool", "output", "offline"].map((x) => (
            <Link key={x} href={`/gates/degradation${x ? `?gate=${x}` : ""}`} className={`rounded-full border px-2 py-0.5 ${gate === x ? "border-primary text-primary" : "border-line"}`}>{x || tr(lang, "전체", "all")}</Link>
          ))}</span>
        </div>
        <div tabIndex={0} className="max-h-80 overflow-auto">
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "에이전트", "Agent")}</th><th>{tr(lang, "계열", "Series")}</th><th>{tr(lang, "관문", "Gate")}</th><th>failMode</th><th>{tr(lang, "타임아웃", "Timeout")}</th><th>{tr(lang, "상태", "Status")}</th></tr></thead>
            <tbody>{modes.map((a: any) => (
              <tr key={a.id}><td><Link className="text-primary" href={`/catalog/${a.id}`}>{a.id}</Link> {nm(lang, a)}</td><td>{a.series}</td><td>{a.gate}</td>
                <td><Chip tone={a.failMode === "closed" ? "primary" : undefined}>{a.failMode}</Chip></td><td>{a.timeoutMs ? `${a.timeoutMs}ms` : tr(lang, "—(비동기)", "— (async)")}</td><td>{a.status}</td></tr>
            ))}</tbody></table>
        </div>
        <p className="p-3 text-xs text-muted">{tr(lang, "DP5 — 인라인 계열(C1·C2)을 fail-open 으로 두면 누락 검증(FR-P16) 빌드 실패. failMode 변경은 에이전트 새 버전 등록으로만.", "DP5 — an inline (C1·C2) agent set to fail-open fails the coverage build (FR-P16). failMode changes only via a new agent version.")}
          {" "}{d.dp5.violations.length ? <b style={{ color: "var(--verdict-block)" }}>{tr(lang, `위반 ${d.dp5.violations.join(", ")}`, `violations ${d.dp5.violations.join(", ")}`)}</b> : tr(lang, "위반 0", "0 violations")}</p>
      </section>
      <section className="card mt-4 overflow-hidden text-sm" data-testid="degrade-history">
        <h2 className="p-3 font-semibold">{tr(lang, `강등 이력 (원장, ${d.days}일 · 추가 전용)`, `Degradation history (ledger, ${d.days} days · append-only)`)}</h2>
        <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "시작", "Start")}</th><th>{tr(lang, "끝", "End")}</th><th>{tr(lang, "관문", "Gate")}</th><th>{tr(lang, "에이전트", "Agent")}</th><th>{tr(lang, "기록", "Records")}</th><th>{tr(lang, "합성 판정", "Verdicts")}</th><th>seq</th><th>{tr(lang, "상태", "State")}</th></tr></thead>
          <tbody>
            {d.episodes.length === 0 && <tr><td colSpan={8} className="text-muted">{tr(lang, "강등 기록 없음", "No degradation records")}</td></tr>}
            {d.episodes.map((e: any) => (
              <tr key={`${e.gate}-${e.agent}-${e.firstSeq}`}><td>{fmtTime(e.start)}</td><td>{fmtTime(e.end)}</td><td>{e.gate}</td><td>{e.agent}</td><td>{e.count}</td>
                <td>{Object.entries(e.verdicts).map(([k, v]) => `${k} ${v}`).join(" · ")}</td>
                <td className="mono"><Link className="text-primary" href={`/evidence?kind=gate`}>{e.firstSeq}–{e.lastSeq}</Link></td>
                <td>{e.active ? <b style={{ color: "var(--verdict-block)" }}>{tr(lang, "진행 중", "active")}</b> : tr(lang, "해제", "cleared")}</td></tr>
            ))}
          </tbody></table>
      </section>
    </>
  );
}
