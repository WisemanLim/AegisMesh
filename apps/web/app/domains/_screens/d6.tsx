// D6 자율 과잉 상세 화면 — SCR-J02 자율 레벨·과업 범위·목표 계약, SCR-J03 실행 계보 목록(상세는 /domains/d6/lineage/[trace]), SCR-J04 자원 쿼터·지출 상한.
import Link from "next/link";
import { Chip, Kpi, VerdictBadge } from "@/components/Badges";
import { Inspector } from "@/components/Inspector";
import { approve, reject } from "@/app/approvals/actions";
import { api, safe } from "@/lib/api";
import { fmtTime, shortHash } from "@/lib/format";
import { tr, LX } from "@/lib/i18n";
import { can } from "@/lib/session";
import { AgentStrip, DetailHeader, Recent, type ScreenProps, SettingsCard } from "./common";

const won = (n?: number | null) => (n == null ? "—" : `₩${Math.round(n).toLocaleString("en-US")}`);

export async function Autonomy({ lang, user, d, screen, sp }: ScreenProps) {
  const target = sp.target || undefined;
  const { data: x } = await safe(api(`/v1/domains/d6/autonomy${target ? `?target=${encodeURIComponent(target)}` : ""}`), null as any);
  if (!x) return <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />;
  const level = (x.contract["d6-01"]?.autonomyLevel ?? x.base["d6-01"]?.autonomyLevel ?? 1) as number;
  const GR = [["I0", "조회 — 검색·읽기", "I0 read — search · read"], ["I1", "내부 쓰기 — 초안 저장", "I1 internal write — save draft"], ["I2", "외부 영향 — 메일·고객 통지", "I2 external — mail · customer notice"],
    ["I3", "고위험 — 이체·배포", "I3 high risk — transfer · deploy"], ["I4", "고위험+외부", "I4 high risk + external"], ["I5", "치명·비가역", "I5 critical · irreversible"]];
  return (
    <>
      <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />
      <AgentStrip lang={lang} ids={["d6-01", "d6-04", "d6-05"]} />
      <div className="mb-3 flex flex-wrap items-center gap-2 text-xs" data-testid="targets">
        <span className="font-semibold">{tr(lang, "보호 대상", "Protected agent")}:</span>
        <Link href="/domains/d6/autonomy" className={`rounded-full border px-2 py-0.5 ${!target ? "border-primary text-primary" : "border-line"}`}>{tr(lang, "공통(기본)", "shared (default)")}</Link>
        {x.targets.map((t: string) => <Link key={t} href={`/domains/d6/autonomy?target=${encodeURIComponent(t)}`} className={`rounded-full border px-2 py-0.5 ${t === target ? "border-primary text-primary" : "border-line"}`}>{t}</Link>)}
      </div>
      <div className="grid grid-cols-2 gap-4">
        <section className="card space-y-2 p-4 text-sm" data-testid="autonomy-table">
          <h2 className="font-semibold">{tr(lang, `① 영향 등급별 자율 레벨 (AG-D6-01) — ${target ?? "공통"} · 레벨 ${level}`, `① Autonomy by impact grade (AG-D6-01) — ${target ?? "shared"} · level ${level}`)}</h2>
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "등급", "Grade")}</th><th>{tr(lang, "처리", "Handling")}</th></tr></thead>
            <tbody>{GR.map(([g, ko, en], i) => <tr key={g}><td>{tr(lang, ko, en)}</td><td style={{ color: i <= level ? "var(--verdict-allow)" : "var(--verdict-approval)" }}>{i <= level ? tr(lang, "자동(기록)", "auto (recorded)") : tr(lang, "사람 승인", "human approval")}</td></tr>)}</tbody></table>
          <div className="grid grid-cols-2 gap-2"><Kpi label={tr(lang, "외부 영향 행동 24h", "External actions 24h")} value={x.external24h} accent="var(--primary)" />
            <Kpi label={tr(lang, "승인 없는 외부 영향 24h", "External without approval 24h")} value={x.externalUnapproved24h} sub={x.externalUnapproved24h === 0 ? "✓" : "⚠"} accent={x.externalUnapproved24h ? "var(--verdict-block)" : "var(--verdict-allow)"} /></div>
          <p className="text-xs text-muted">{tr(lang, "등급 = impact(low 0·medium 1·high 2·critical 3) + 외부 1 + 비가역 1. 레벨 초과 → 사람 승인(require_approval), 승인 결과는 승인 사건으로", "Grade = impact (low 0 · medium 1 · high 2 · critical 3) + external 1 + irreversible 1. Above the level → human approval, recorded as an approval event")}</p>
        </section>
        <SettingsCard lang={lang} user={user} id="d6-01" principal={target} title={tr(lang, `자율 레벨 — ${target ?? "공통"}`, `Autonomy level — ${target ?? "shared"}`)} />
      </div>
      <div className="mt-4 grid grid-cols-2 gap-4">
        <SettingsCard lang={lang} user={user} id="d6-04" principal={target} title={tr(lang, `② 과업 범위 계약 (AG-D6-04) — ${target ?? "공통"}`, `② Task-scope contract (AG-D6-04) — ${target ?? "shared"}`)} />
        <section className="card space-y-2 p-4 text-sm" data-testid="scope-blocks">
          <h2 className="font-semibold">{tr(lang, "범위 밖 계획·도구 차단 (24h)", "Out-of-scope plans · tools blocked (24h)")}</h2>
          <ul className="space-y-1 text-xs">{x.scopeBlocks.length === 0 ? <li className="text-muted">{tr(lang, "없음", "None")}</li> : x.scopeBlocks.map((f: any) => (
            <li key={f.id}><VerdictBadge v={f.effective ?? f.verdict} /> {fmtTime(f.at)} · {f.principal} · <Link className="text-primary mono" href={`/domains/d3/calls/${f.traceId}`}>{f.ruleId}</Link> — {f.evidence.map((e: any) => LX(lang, e.note)).join("; ")}</li>))}</ul>
          <p className="text-xs text-muted">{tr(lang, "계약 밖 하위 과업·도구 = 차단, 범위 변경은 승인 사건(정책 계약 배포)으로", "Out-of-contract subtasks/tools are blocked; scope changes go through an approval (contract deploy)")}</p>
        </section>
      </div>
      <div className="mt-4 grid grid-cols-2 gap-4">
        <div className="space-y-4">
          <SettingsCard lang={lang} user={user} id="d6-05" principal={target} title={tr(lang, `③ 목표 불변식·금지 수단 (AG-D6-05) — ${target ?? "공통"}`, `③ Goal invariants · forbidden means (AG-D6-05) — ${target ?? "shared"}`)} />
          <section className="card space-y-2 p-4 text-sm" data-testid="alignment">
            <h2 className="font-semibold">{tr(lang, "정렬 평가 세트 (레드팀 캠페인)", "Alignment evaluation (red-team campaign)")}</h2>
            <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "에이전트", "Agent")}</th><th>{tr(lang, "통과율(탐지)", "Pass (detection)")}</th><th>{tr(lang, "기준", "Baseline")}</th><th>{tr(lang, "오탐", "FP")}</th></tr></thead>
              <tbody>{Object.entries(x.alignment).map(([a, r]: [string, any]) => <tr key={a}><td>{a}</td><td style={{ color: r && r.detectionRate < r.baseline ? "var(--verdict-block)" : undefined }}>{r ? `${(r.detectionRate * 100).toFixed(1)}%` : "—"}</td><td>{r ? `${(r.baseline * 100).toFixed(0)}%` : "—"}</td><td>{r ? `${(r.fpRate * 100).toFixed(1)}%` : "—"}</td></tr>)}</tbody></table>
            <p className="text-xs text-muted">{tr(lang, `최근 ${x.alignmentAt ? fmtTime(x.alignmentAt) : "—"} · 상시(레드팀 스케줄) — 실패 사례는 골든셋 편입`, `latest ${x.alignmentAt ? fmtTime(x.alignmentAt) : "—"} · continuous (red-team schedule) — failures go to the golden set`)} · <Link className="text-primary" href="/redteam">{tr(lang, "레드팀 ›", "Red team ›")}</Link></p>
            <ul className="text-xs">{x.means.slice(0, 5).map((f: any) => <li key={f.id}><VerdictBadge v={f.effective ?? f.verdict} /> {f.principal} · {f.ruleId} — {f.evidence.map((e: any) => LX(lang, e.note)).join("; ")}</li>)}</ul>
          </section>
        </div>
        <section className="card p-4 text-sm"><h2 className="mb-2 font-semibold">{tr(lang, "시험 입력 (보호 대상 계약 적용, 저장 안 함)", "Test input (target contract applied, no save)")}</h2>
          <Inspector agents={["d6-04", "d6-01", "d6-05"].map((id) => ({ id, label: id }))} samples={{
            "d6-04": { tool: { name: "credit.query" }, plan: ["신청 서류 수집", "신용 조회 요약", "신용정보 추가 조회"], subject: { principal: { id: target ?? "loan-review-agent" } } },
            "d6-01": { action: { type: "customer.notify", impact: "medium", external: true }, subject: { principal: { id: target ?? "loan-review-agent" } } },
            "d6-05": { plan: ["승인율 목표를 위해 서류 누락 검사를 skip the checks"], subject: { principal: { id: target ?? "loan-review-agent" } } } }} /></section>
      </div>
    </>
  );
}

export async function Lineage({ lang, d, screen, sp }: ScreenProps) {
  const { data } = await safe(api("/v1/domains/d6/runs"), { items: [] as any[] });
  return (
    <>
      <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />
      <AgentStrip lang={lang} ids={["d6-02", "d6-03"]} />
      <section className="card overflow-hidden text-sm" data-testid="runs">
        <h2 className="p-3 font-semibold">{tr(lang, "실행 — 계보(history)가 있거나 재귀·루프 판정이 난 도구 관문 호출", "Runs — tool-gate calls with lineage (history) or recursion/loop verdicts")}</h2>
        <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "시각", "Time")}</th><th>run</th><th>{tr(lang, "주체", "Principal")}</th><th>{tr(lang, "단계", "Steps")}</th><th>{tr(lang, "깊이", "Depth")}</th><th>{tr(lang, "판정", "Verdict")}</th><th>{tr(lang, "규칙", "Rules")}</th></tr></thead>
          <tbody>{data.items.length === 0 ? <tr><td colSpan={7} className="text-muted">{tr(lang, "실행 기록 없음", "No runs")}</td></tr> : data.items.map((r: any) => (
            <tr key={r.traceId}><td>{fmtTime(r.at)}</td><td className="mono"><Link className="text-primary" href={`/domains/d6/lineage/${r.traceId}`}>{shortHash(r.traceId)}</Link></td><td>{r.principal ?? "—"}</td><td>{r.steps}</td><td>{r.depth}</td><td><VerdictBadge v={r.verdict} /></td><td className="mono">{r.rules.join(", ") || "—"}</td></tr>))}</tbody></table>
      </section>
    </>
  );
}

export async function Budgets({ lang, user, d, screen, sp }: ScreenProps) {
  const { data: x } = await safe(api("/v1/domains/d6/budgets"), null as any);
  if (!x) return <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />;
  const daily = x.limits.dailyLimit as number | undefined;
  return (
    <>
      <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />
      <AgentStrip lang={lang} ids={["d6-06", "d6-07"]} />
      <div className="grid grid-cols-2 gap-4">
        <section className="card space-y-2 p-4 text-sm" data-testid="quotas">
          <h2 className="font-semibold">{tr(lang, "① 주체별 자원 쿼터 (AG-D6-06)", "① Resource quotas by principal (AG-D6-06)")}</h2>
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "주체", "Principal")}</th><th>{tr(lang, "쿼터 (tokens · seconds · concurrency · storageMb · costUsd)", "Quota (tokens · seconds · concurrency · storageMb · costUsd)")}</th></tr></thead>
            <tbody><tr><td>{tr(lang, "공통", "shared")}</td><td className="mono">{JSON.stringify(x.quota.base.quota ?? {})}</td></tr>
              {Object.entries(x.quota.byPrincipal).map(([p, v]: [string, any]) => <tr key={p}><td>{p}</td><td className="mono">{JSON.stringify(v.quota ?? {})}</td></tr>)}</tbody></table>
          <ul className="space-y-1 text-xs">{x.quotaEvents.length === 0 ? <li className="text-muted">{tr(lang, "쿼터 근접·초과 없음 (24h)", "No quota near/over events (24h)")}</li> : x.quotaEvents.slice(0, 8).map((f: any) => (
            <li key={f.id}><VerdictBadge v={f.effective ?? f.verdict} /> {f.principal} · {f.ruleId} — {f.evidence.map((e: any) => LX(lang, e.note)).join("; ")}</li>))}</ul>
          <p className="text-xs text-muted">{tr(lang, "근접(90%) = 백프레셔 권고 — 대기열·429·강등 실행(소형 모델·요약 모드)은 호출자, 초과 = 새 실행 거부. 사용량은 호출자가 params.usage 로", "Near (90%) = back-pressure advice — queue · 429 · degraded run (small model · summary mode) is the caller's; over = new runs refused. Usage comes from the caller via params.usage")}</p>
        </section>
        <section className="card space-y-2 p-4 text-sm" data-testid="spend">
          <h2 className="font-semibold">{tr(lang, "② 지출 상한 (AG-D6-07) — 오늘 관문 관측", "② Spend limits (AG-D6-07) — observed today at the gate")}</h2>
          <p className="text-xs">{tr(lang, `건당 상한 ${won(x.limits.spendLimit ?? 10000000)} · 승인 임계 ${won(x.limits.approvalThreshold ?? 100000)} 초과 = 2인 승인 · 일 상한 ${won(daily)}`, `per-tx limit ${won(x.limits.spendLimit ?? 10000000)} · above ${won(x.limits.approvalThreshold ?? 100000)} = two approvals · daily ${won(daily)}`)}</p>
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "주체", "Principal")}</th><th>{tr(lang, "실행", "Executed")}</th><th>{tr(lang, "승인 대기", "Pending")}</th><th>{tr(lang, "차단", "Blocked")}</th><th>{tr(lang, "일 상한 대비", "Of daily")}</th></tr></thead>
            <tbody>{x.spend.length === 0 ? <tr><td colSpan={5} className="text-muted">{tr(lang, "오늘 금전 행동 없음", "No money actions today")}</td></tr> : x.spend.map((r: any) => (
              <tr key={r.principal}><td>{r.principal}</td><td>{won(r.executed)}</td><td>{won(r.pending)}</td><td>{won(r.blocked)}</td><td>{daily ? `${Math.round((r.executed / daily) * 100)}%` : "—"}</td></tr>))}</tbody></table>
        </section>
      </div>
      <section className="card mt-4 space-y-2 p-4 text-sm" data-testid="money-approvals">
        <h2 className="font-semibold">{tr(lang, "되돌릴 수 없는 금전 행동 — 2인 승인", "Irreversible money actions — two approvals")}</h2>
        {x.approvals.length === 0 ? <p className="text-xs text-muted">{tr(lang, "대기 중인 금전 승인 없음", "No pending money approvals")}</p> : x.approvals.map((c: any) => (
          <div key={c.id} className="flex flex-wrap items-center gap-2 rounded border border-line p-2 text-xs">
            <VerdictBadge v={c.effective ?? c.verdict} /><span>{c.principal}</span><span className="mono">{c.ruleId}</span><span>{c.evidence.map((e: any) => LX(lang, e.note)).join("; ")}</span>
            <Chip>{c.approval.id} · {c.approval.status} · {c.approval.decisions.filter((x: any) => x.decision === "approve").length}/{c.approval.required}</Chip>
            {c.approval.status === "pending" && can(user, "approve") && (
              <form className="ml-auto flex gap-1"><input type="hidden" name="id" value={c.approval.id} /><input type="hidden" name="back" value="/domains/d6/budgets" />
                <input name="reason" required className="input h-7 w-48 text-xs" placeholder={tr(lang, "사유 (필수)", "Reason (required)")} aria-label="reason" />
                <button formAction={approve} className="btn btn-primary h-7 text-xs">{tr(lang, "승인", "Approve")}</button><button formAction={reject} className="btn btn-secondary h-7 text-xs">{tr(lang, "거절", "Reject")}</button></form>)}
          </div>))}
        <p className="text-xs text-muted">{tr(lang, "요청자·첫 승인자는 두 번째 승인 불가(MSG-011) · 결정은 원장 기록", "The requester and first approver cannot give the second approval (MSG-011) · decisions are ledgered")}</p>
      </section>
      <div className="mt-4 grid grid-cols-2 gap-4">
        <SettingsCard lang={lang} user={user} id="d6-07" title={tr(lang, "지출 상한 · 보상 트랜잭션 {행동: 보상 행동} (D6-07)", "Spend limits · compensations {action: compensating action} (D6-07)")} />
        <SettingsCard lang={lang} user={user} id="d6-06" title={tr(lang, "자원 쿼터 (D6-06)", "Resource quotas (D6-06)")} />
      </div>
      <div className="mt-4"><Recent lang={lang} ids={["d6-06", "d6-07"]} /></div>
    </>
  );
}
