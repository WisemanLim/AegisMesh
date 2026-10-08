// SCR-C07 즉시 사용 ④ 적용 단계·해제 — 관측만·부분 차단(도메인 선택)·전체 차단(승인), 예상 영향 재계산, 계열별 강등 정책 확인, 프로파일 해제(이전 스냅샷 복귀).
import Link from "next/link";
import { Banner, Chip } from "@/components/Badges";
import { ConfirmButton } from "@/components/ConfirmButton";
import { InstantSteps } from "@/components/InstantSteps";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { t as tk, tr } from "@/lib/i18n";
import { domainName } from "@/lib/riskmap";
import { can, me, prefs } from "@/lib/session";
import { applyStage, recompute, rollbackTarget } from "../wizard-actions";

const DOMAINS = ["D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "D10", "X"];
const DEFAULT_BLOCK = ["D1", "D2", "D3", "D5", "D6"];
const STAGES: [string, string, string, string, string][] = [
  ["observe", "관측만", "Observe only", "차단 없이 alert 만 기록 · L1 가시성 · 요청 영향 없음", "alert only, no blocking · L1 visibility · no request impact"],
  ["partial", "부분 차단", "Partial blocking", "선택 도메인만 block · L2 선택 차단 · 권장 시작점", "selected domains block · L2 · recommended start"],
  ["enforce", "전체 차단", "Full blocking", "프로파일 정책 그대로 차단 · L3 · 승인자 승인", "blocks per profile policy · L3 · needs approver"],
];
// 계열별 failMode 기본값 (매니페스트 명시값 우선) — FR-P15
const FAIL: [string, string, string, string, string][] = [
  ["C1", "입출력", "Input/output", "closed", "D1 · D4"], ["C2", "도구", "Tool", "closed", "D3 · D5 · D6"],
  ["C3", "상시", "Always-on", "open", "D2 · X08"], ["C4", "증적", "Evidence", "open", "D10"],
];
const V: Record<string, string> = { allow: "#257a6e", alert: "#9d6105", transform: "#3b6fd8", require_approval: "#8a4fd8", block: "#c03333" };

export default async function InstantApply({ searchParams }: { searchParams: Promise<{ p?: string; t?: string; stage?: string; d?: string; msg?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const sp = await searchParams;
  const { p, t, msg } = sp;
  const stage = sp.stage ?? "partial";
  const picked = sp.d !== undefined ? sp.d.split(",").filter(Boolean) : DEFAULT_BLOCK;
  const write = can(user, "policy.write");
  const [targets, preview] = await Promise.all([
    safe(api("/v1/targets"), { items: [] as any[] }),
    p ? safe(api(`/v1/profiles/${encodeURIComponent(p)}:preview`, { method: "POST", body: JSON.stringify({ stage: stage === "observe" ? "observe" : "enforce",
      ...(stage === "partial" ? { alertDomains: DOMAINS.filter((d) => !picked.includes(d)) } : {}) }) }), null as any) : Promise.resolve({ data: null as any, error: undefined }),
  ]);
  const tgt = targets.data.items.find((x: any) => x.name === t);
  const pv = preview.data;
  const fp = pv?.estimate?.falsePositiveRate;
  const enforceOff = fp != null && fp > 0.005;
  const ready = !!p && !!tgt;
  return (
    <>
      <PageHeader crumb={`${tk(lang, "instant")} › ${tr(lang, "적용", "Apply")}`} title={tr(lang, "즉시 사용 ④ 적용 단계 · 해제", "Instant use ④ apply stage · release")} />
      <InstantSteps lang={lang} at={4} p={p} t={t} />
      {msg && <div className="mb-3"><Banner tone={/^(실패|Failed)/.test(msg) ? "danger" : "info"}>{msg}</Banner></div>}
      {!ready && <div className="mb-3"><Banner tone="warn">{tr(lang, "① 프로파일과 ② 보호 대상을 먼저 고른다 (MSG-003)", "Choose a profile (①) and a target (②) first (MSG-003)")}</Banner></div>}
      {tgt?.application && <div className="mb-3" data-testid="current-app"><Banner tone="info">{tr(lang, `현재 ${t}: ${tgt.application.profile} · ${tgt.application.stage}`, `Now on ${t}: ${tgt.application.profile} · ${tgt.application.stage}`)}</Banner></div>}
      <form action={applyStage} className="space-y-4" data-testid="apply-form">
        <input type="hidden" name="p" value={p ?? ""} /><input type="hidden" name="t" value={t ?? ""} />
        <fieldset role="radiogroup" aria-label="stage" className="grid grid-cols-3 gap-3">
          {STAGES.map(([v, ko, en, dko, den]) => {
            const off = v === "enforce" && enforceOff;
            return (
              <label key={v} className={`card flex cursor-pointer flex-col gap-1 p-4 text-sm ${stage === v ? "ring-2 ring-primary" : ""} ${off ? "opacity-50" : ""}`}>
                <span className="flex items-center gap-2"><input type="radio" name="stage" value={v} defaultChecked={stage === v} disabled={off} /><b>{tr(lang, ko, en)}</b>
                  {v === "partial" && <Chip tone="primary">{tr(lang, "권장", "Recommended")}</Chip>}</span>
                <span className="text-xs text-muted">{tr(lang, dko, den)}</span>
                {off && <span className="text-xs" style={{ color: "var(--verdict-block)" }}>{tr(lang, `미리보기 오탐 추정 ${(fp * 100).toFixed(1)}% > 0.5% — 전체 차단 비활성`, `Preview FP estimate ${(fp * 100).toFixed(1)}% > 0.5% — full blocking disabled`)}</span>}
              </label>
            );
          })}
        </fieldset>
        <div className="grid grid-cols-[1fr_1fr] gap-4">
          <section className="card p-4 text-sm" data-testid="partial-domains">
            <h2 className="mb-2 font-semibold">{tr(lang, "부분 차단 대상 — 체크 해제 도메인은 alert 로 기록(차단 안 함)", "Partial blocking — unchecked domains are recorded as alert (not blocked)")}</h2>
            <div className="grid grid-cols-2 gap-1 text-xs">{DOMAINS.map((d) => (
              <label key={d} className="flex items-center gap-1.5"><input type="checkbox" name="d" value={d} defaultChecked={picked.includes(d)} />{d} {domainName(lang, d)}</label>))}</div>
            <p className="mt-2 text-xs text-muted">{tr(lang, "부분 차단을 고를 때만 쓰인다 · 바꾸면 아래 '예상 영향 재계산'", "Used only for partial blocking · change, then 'Recompute impact'")}</p>
          </section>
          <section className="card p-4 text-sm" data-testid="impact">
            <h2 className="mb-2 font-semibold">{tr(lang, "예상 영향 (③ 미리보기 재계산)", "Expected impact (③ preview recomputed)")} — {tr(lang, STAGES.find((s) => s[0] === stage)?.[1] ?? stage, STAGES.find((s) => s[0] === stage)?.[2] ?? stage)}</h2>
            {pv ? (<>
              <div className="grid grid-cols-5 gap-2 text-center">{Object.entries(pv.counts).map(([v, n]: [string, any]) => <div key={v}><div className="text-xs" style={{ color: V[v] }}>{v}</div><b className="text-lg">{n}</b></div>)}</div>
              <p className="mt-2 text-xs text-muted">{tr(lang, "표본", "Samples")} {pv.samples} · {tr(lang, "오탐 추정", "FP estimate")} {fp == null ? "—" : `${(fp * 100).toFixed(1)}%`} · {tr(lang, "미탐 추정", "miss estimate")} {pv.estimate.missRate == null ? "—" : `${(pv.estimate.missRate * 100).toFixed(1)}%`}</p>
            </>) : <p className="text-xs text-muted">{preview.error ?? "—"}</p>}
            <button formAction={recompute} formNoValidate className="btn btn-secondary mt-2 h-7 text-xs" data-testid="recompute">{tr(lang, "예상 영향 재계산", "Recompute impact")}</button>
          </section>
        </div>
        <section className="card p-4 text-sm" data-testid="failmode">
          <h2 className="mb-2 font-semibold">{tr(lang, "강등 정책 (fail mode) — 계열 기본 타임아웃 시 동작 · 매니페스트 명시값 우선", "Degradation policy (fail mode) — behaviour on timeout per family · manifest values win")}</h2>
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "계열", "Family")}</th><th>failMode</th><th>{tr(lang, "강등 시", "When degraded")}</th><th>{tr(lang, "도메인", "Domains")}</th></tr></thead>
            <tbody>{FAIL.map(([c, ko, en, m, d]) => <tr key={c}><td>{c} {tr(lang, ko, en)}</td><td><b style={{ color: m === "closed" ? "var(--verdict-block)" : "#9d6105" }}>{m}</b></td>
              <td>{m === "closed" ? tr(lang, "차단", "block") : c === "C4" ? tr(lang, "버퍼 적재", "buffer") : tr(lang, "통과 + 경보", "pass + alert")}</td><td>{d}</td></tr>)}</tbody></table>
          <label className="mt-2 flex items-center gap-2 text-xs"><input type="checkbox" name="confirmed" required data-testid="confirm-failmode" />{tr(lang, "강등 시 배너·증적 기록을 확인했습니다 (필수 — MSG-003)", "I checked the degradation banner and evidence recording (required — MSG-003)")}</label>
          <Link className="text-xs text-primary" href="/gates/degradation">{tr(lang, "강등 현황 ›", "Degradation status ›")}</Link>
        </section>
        <div className="flex items-center gap-3">
          <ConfirmButton className="btn btn-primary" disabled={!ready || !write} message={tr(lang, `${t} 에 ${p} 적용 — 정책은 10초 안에 반영된다. 계속할까? (MSG-018)`, `Apply ${p} to ${t} — policy goes live within 10 s. Continue? (MSG-018)`)}>
            {tr(lang, "적용", "Apply")}</ConfirmButton>
          <span className="text-xs text-muted">{tr(lang, "적용·해제 모두 증적 기록 · 일부 관문 실패 시 성공분 유지, 실패만 재시도 (ST-05)", "Apply and release are both recorded · on partial gate failure, successes stay and only failures retry (ST-05)")}</span>
        </div>
      </form>
      <section className="card mt-4 flex items-center gap-3 p-4 text-sm" data-testid="rollback">
        <b>{tr(lang, "되돌리기", "Roll back")}</b>
        <span className="text-xs text-muted">{tr(lang, "프로파일 해제 = 이전 스냅샷으로 즉시 복귀(없으면 미적용) · 증적 기록", "Release = return to the previous snapshot at once (or none) · recorded")}</span>
        <form action={rollbackTarget} className="ml-auto"><input type="hidden" name="p" value={p ?? ""} /><input type="hidden" name="t" value={t ?? ""} />
          <ConfirmButton className="btn btn-danger" disabled={!tgt?.application || !write} message={tr(lang, `${t} 의 ${tgt?.application?.profile ?? ""} 해제 — 이전 스냅샷으로 복귀한다. 계속할까? (MSG-019)`, `Release ${tgt?.application?.profile ?? ""} on ${t} — returns to the previous snapshot. Continue? (MSG-019)`)}>
            {tr(lang, "프로파일 해제 (롤백)", "Release profile (roll back)")}</ConfirmButton></form>
      </section>
    </>
  );
}
