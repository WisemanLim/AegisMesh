// D4 모델 환각 상세 화면 — SCR-H02 근거성·인용(목록 · 상세는 /domains/d4/grounding/[fid]), SCR-H03 결정 신뢰도·논리·규정, SCR-H04 오정보 전파·신뢰 지표.
import Link from "next/link";
import { Kpi, VerdictBadge } from "@/components/Badges";
import { Inspector } from "@/components/Inspector";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { tr, LX } from "@/lib/i18n";
import { can } from "@/lib/session";
import { correctPoint, retroCorrect } from "../actions";
import { AgentStrip, DetailHeader, Recent, type ScreenProps, SettingsCard } from "./common";

const GROUND_SAMPLE = { output: "중도상환수수료는 3년 이내 1.2%입니다. 면제 대상은 모든 대출입니다 2026년. 근거: https://garam.example/fee, 금융위 고시 doi:10.9999/fsc.2026-31",
  retrieval: [{ id: "kb/fee-policy-2026.pdf", url: "https://garam.example/fee", text: "중도상환수수료는 대출 실행일로부터 3년 이내 상환 시 잔액의 1.2%를 부과한다" }] };

export async function GroundingList({ lang, user, d, screen, sp }: ScreenProps) {
  return (
    <>
      <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />
      <AgentStrip lang={lang} ids={["d4-01", "d4-02"]} />
      <div className="grid grid-cols-2 gap-4">
        <Recent lang={lang} ids={["d4-01", "d4-02"]} title={tr(lang, "근거성·인용 판정 — 행을 열면 문장 단위 근거·인용 검증", "Groundedness & citation verdicts — open for sentence-level evidence and citation checks")} />
        <section className="card p-4 text-sm">
          <h2 className="mb-2 font-semibold">{tr(lang, "시험 입력 — 문장 근거성·인용 실재 (저장 안 함)", "Test input — sentence groundedness · citation existence (no save)")}</h2>
          <Inspector agents={[{ id: "d4-01", label: "d4-01" }, { id: "d4-02", label: "d4-02" }]} samples={{ "d4-01": GROUND_SAMPLE, "d4-02": GROUND_SAMPLE }} />
        </section>
      </div>
      <div className="mt-4 grid grid-cols-2 gap-4">
        <SettingsCard lang={lang} user={user} id="d4-01" showRules title={tr(lang, "모드 — 표시 우선(transform·alert) / 차단(block): D4-01 규칙 재정의", "Mode — display first (transform · alert) / block: D4-01 rule override")} />
        <SettingsCard lang={lang} user={user} id="d4-02" showRules title={tr(lang, "인용 실재 목록 · 목록 밖 URL 허용 (D4-02)", "Known citations · allow unlisted URLs (D4-02)")} />
      </div>
    </>
  );
}

export async function Decisions({ lang, user, d, screen, sp }: ScreenProps) {
  const [{ data: x }, cfg, dict] = await Promise.all([
    safe(api("/v1/domains/d4/decisions"), null as any), safe(api("/v1/agents/d4-03/config"), null as any),
    safe(api("/v1/agents/d4-05:inspect", { method: "POST", body: JSON.stringify({ request: { output: "" } }) }), null as any),
  ]);
  const th: Record<string, number> = cfg.data?.values?.thresholdsByAction ?? {};
  const def = cfg.data?.effective?.decisionThreshold ?? 0.75;
  return (
    <>
      <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />
      <AgentStrip lang={lang} ids={["d4-03", "d4-04", "d4-05"]} />
      <div className="grid grid-cols-2 gap-4">
        <section className="card space-y-2 p-4 text-sm" data-testid="decision-thresholds">
          <h2 className="font-semibold">{tr(lang, "① 결정 신뢰도 게이트 (AG-D4-03) — 행동별 임계", "① Decision-confidence gate (AG-D4-03) — threshold by action")}</h2>
          {[...Object.entries(th), [tr(lang, "그 외(기본)", "other (default)"), def] as [string, number]].map(([k, v]) => (
            <div key={k} className="flex items-center gap-2 text-xs"><span className="w-28">{k}</span>
              <div className="h-2 flex-1 rounded bg-[#eef0f4]"><div className="h-2 rounded" style={{ width: `${v * 100}%`, background: "var(--primary)" }} /></div><b className="w-10 text-right">{v}</b></div>
          ))}
          <p className="text-xs text-muted">{tr(lang, `신뢰도 < 임계 → 사람 승인(require_approval), 승인 없으면 실행 안 함 · < ${cfg.data?.effective?.blockBelow ?? 0.3} 이면 차단`, `confidence < threshold → human approval (require_approval); no approval, no execution · below ${cfg.data?.effective?.blockBelow ?? 0.3} → block`)}</p>
          <h3 className="pt-2 font-semibold">{tr(lang, "② 임계 미만 결정 (7일)", "② Below-threshold decisions (7 days)")}</h3>
          <ul className="space-y-1 text-xs" data-testid="low-confidence">{(x?.lowConfidence ?? []).length === 0 ? <li className="text-muted">{tr(lang, "없음", "None")}</li> : x.lowConfidence.slice(0, 8).map((f: any) => (
            <li key={f.id} className="flex items-center gap-2"><VerdictBadge v={f.effective ?? f.verdict} /><Link className="text-primary mono inline-flex min-h-6 items-center" href={`/domains/d3/calls/${f.traceId}`}>{f.ruleId}</Link>
              <span>{f.evidence.map((e: any) => LX(lang, e.note)).join("; ")}</span>{f.approval && <Link className="ml-auto text-primary" href="/approvals">{f.approval.id} · {f.approval.status} ›</Link>}</li>))}</ul>
        </section>
        <SettingsCard lang={lang} user={user} id="d4-03" title={tr(lang, "d4-03 설정 — thresholdsByAction {payment: 0.9, deploy: 0.85, notify: 0.8}", "d4-03 settings — thresholdsByAction {payment: 0.9, deploy: 0.85, notify: 0.8}")} />
      </div>
      <div className="mt-4 grid grid-cols-2 gap-4">
        <section className="card space-y-2 p-4 text-sm" data-testid="logic">
          <h2 className="font-semibold">{tr(lang, "③ 논리 검사 (AG-D4-04) — 검증자 재실행 · 자기일관성", "③ Logic checks (AG-D4-04) — verifier re-run · self-consistency")}</h2>
          <Inspector agents={[{ id: "d4-04", label: "d4-04" }]} samples={{ "d4-04": { output: "대출 원금 100,000,000원, 이자율 연 12.4% → 월 이자 100,000,000 * 0.124 = 12,400,000원", params: { samples: ["월 이자 1,033,333원", "월 이자 1,033,333원", "월 이자 12,400,000원"] } } }} />
        </section>
        <section className="card space-y-2 p-4 text-sm" data-testid="compliance">
          <h2 className="font-semibold">{tr(lang, "④ 규정 위반 출력 (AG-D4-05) — 정책 룰 · 도메인 금칙 사전", "④ Compliance (AG-D4-05) — policy rules · domain prohibited phrases")}</h2>
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "규칙", "Rule")}</th><th>{tr(lang, "출처", "Source")}</th><th>{tr(lang, "조치", "Action")}</th></tr></thead>
            <tbody>{(dict.data?.explain?.rules ?? []).map((r: any) => <tr key={r.rule}><td className="mono">{r.rule}</td><td>{r.source === "builtin" ? tr(lang, "내장 사전", "built-in") : tr(lang, "조직 사전", "organization")}</td><td>{r.verdict === "block" ? tr(lang, "차단", "block") : tr(lang, "재작성", "rewrite")}</td></tr>)}</tbody></table>
          <p className="text-xs text-muted">{tr(lang, `사전: 내장 ${dict.data?.explain?.dictionary?.builtin ?? "—"} + 조직 ${dict.data?.explain?.dictionary?.org ?? 0} · 편집은 정책 쓰기 권한(규제 대응 검토 후 배포)`, `Dictionary: built-in ${dict.data?.explain?.dictionary?.builtin ?? "—"} + organization ${dict.data?.explain?.dictionary?.org ?? 0} · edits need policy-write (deploy after compliance review)`)}</p>
          <Inspector agents={[{ id: "d4-05", label: "d4-05" }]} samples={{ "d4-05": { output: "이 상품은 원금 보장 상품이며 지금 당장 매수하세요. 제휴 상품입니다." } }} />
        </section>
      </div>
      <div className="mt-4 grid grid-cols-2 gap-4">
        <SettingsCard lang={lang} user={user} id="d4-05" title={tr(lang, "d4-05 — 조직 금칙 사전 [{pattern, rule, verdict}]", "d4-05 — organization dictionary [{pattern, rule, verdict}]")} />
        <Recent lang={lang} ids={["d4-03", "d4-04", "d4-05"]} />
      </div>
    </>
  );
}

const STATUS: Record<string, [string, string, string]> = { pending: ["대기", "Pending", "var(--sev-info)"], requested: ["정정 요청", "Requested", "#3b6fd8"], quarantined: ["격리", "Quarantined", "#9d6105"],
  corrected: ["정정 완료", "Corrected", "var(--verdict-allow)"], gate_blocked: ["게이트 차단", "Gate blocked", "var(--verdict-block)"] };

export async function Propagation({ lang, user, d, screen, sp }: ScreenProps) {
  const { data: x } = await safe(api("/v1/domains/d4/propagation"), null as any);
  const m = x?.metrics ?? {};
  const pct = (v?: number | null, dg = 1) => (v == null ? "—" : `${(v * 100).toFixed(dg)}%`);
  const write = can(user, "incident");
  return (
    <>
      <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />
      <AgentStrip lang={lang} ids={["d4-06", "d4-07"]} />
      <section className="card space-y-3 p-4 text-sm" data-testid="propagation">
        <h2 className="font-semibold">{tr(lang, "① 전파 경로 — 출처별 지점 (AG-D4-06)", "① Propagation paths — points by source (AG-D4-06)")}</h2>
        {(x?.sources ?? []).length === 0 ? <p className="text-xs text-muted">{tr(lang, "전파 판정 없음 — 출력이 agent·document·index·memory 로 나갈 때(params.destination) D4-06 이 출처 표기·검증 상태를 본다", "No propagation verdicts — D4-06 checks provenance and verification when output goes to agent · document · index · memory (params.destination)")}</p>
          : x.sources.map((src: any) => (
            <div key={src.source} className="rounded-lg border border-line p-3">
              <div className="mb-2 flex flex-wrap items-center gap-2 text-xs">
                <span className="rounded bg-navy px-2 py-0.5 text-white">{src.source === "출처 미표기" ? tr(lang, "출처 미표기", "no provenance") : src.source}</span>
                {src.total > src.points.length && <span className="text-muted">{tr(lang, `최근 ${src.points.length} / ${src.total}`, `latest ${src.points.length} of ${src.total}`)}</span>}
                {src.points.map((p: any) => <span key={p.traceId} className="flex items-center gap-1">→ <span className="rounded border px-2 py-0.5" style={{ borderColor: STATUS[p.status][2], color: STATUS[p.status][2] }}>{p.destination} · {tr(lang, STATUS[p.status][0], STATUS[p.status][1])}</span></span>)}
                {write && src.source !== "출처 미표기" && <form action={retroCorrect} className="ml-auto"><input type="hidden" name="source" value={src.source} /><button className="btn btn-secondary h-7 text-xs">{tr(lang, "소급 정정 실행", "Run retroactive correction")}</button></form>}
              </div>
              <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "시각", "Time")}</th><th>{tr(lang, "전파 지점", "Point")}</th><th>{tr(lang, "판정", "Verdict")}</th><th>{tr(lang, "규칙", "Rule")}</th><th>{tr(lang, "상태", "Status")}</th><th></th></tr></thead>
                <tbody>{src.points.map((p: any) => (
                  <tr key={p.traceId}><td>{fmtTime(p.at)}</td><td>{p.destination}</td><td><VerdictBadge v={p.verdict} /></td><td className="mono"><Link className="text-primary" href={`/findings/${p.finding}`}>{p.ruleId}</Link></td>
                    <td style={{ color: STATUS[p.status][2] }}>{tr(lang, STATUS[p.status][0], STATUS[p.status][1])}{p.correctedAt && ` · ${fmtTime(p.correctedAt)}`}</td>
                    <td>{write && <form action={correctPoint} className="flex gap-1"><input type="hidden" name="traceId" value={p.traceId} />
                      <select name="status" className="input h-6 text-xs" defaultValue="corrected" aria-label="status">{["quarantined", "corrected", "requested"].map((s) => <option key={s} value={s}>{tr(lang, STATUS[s][0], STATUS[s][1])}</option>)}</select>
                      <button className="btn btn-secondary h-6 text-xs">{tr(lang, "기록", "Record")}</button></form>}</td></tr>))}</tbody></table>
            </div>))}
        <p className="text-xs text-muted">{tr(lang, "정정 이력은 증적 원장(추가 전용, MSG-016). 소급 정정 = 출처에서 퍼진 지점 중 완료·차단이 아닌 것에 정정 요청(실패만 재시도, MSG-028).", "Correction history is in the evidence ledger (append-only, MSG-016). Retroactive correction = request fixes for every point not yet corrected or blocked (retry failures only, MSG-028).")}</p>
      </section>
      <div className="mt-4 grid grid-cols-2 gap-4">
        <div className="space-y-4">
          <section className="card space-y-2 p-4 text-sm" data-testid="trust-metrics">
            <h2 className="font-semibold">{tr(lang, "③ 신뢰 지표 (AG-D4-07, 7일 대 전주)", "③ Trust metrics (AG-D4-07, 7 days vs previous)")}</h2>
            <div className="grid grid-cols-2 gap-2">
              <Kpi label={tr(lang, "근거성 점수", "Groundedness")} value={m.groundedness ?? "—"} sub={m.groundednessPrev != null ? tr(lang, `전주 ${m.groundednessPrev}`, `prev ${m.groundednessPrev}`) : undefined} accent={m.groundedness != null && m.groundednessPrev != null && m.groundedness < m.groundednessPrev - 0.05 ? "var(--verdict-block)" : "var(--verdict-allow)"} />
              <Kpi label={tr(lang, "사용자 부정 피드백", "Negative feedback")} value={pct(m.negativeFeedback, 2)} accent="#9d6105" />
              <Kpi label={tr(lang, "불확실성 미표기", "Missing uncertainty")} value={pct(m.uncertaintyMissing)} accent="var(--sev-info)" />
              <Kpi label={tr(lang, "정정 후 재발", "Recurrence after fix")} value={m.recurrence ?? 0} accent={m.recurrence ? "var(--verdict-block)" : "var(--verdict-allow)"} />
            </div>
            {(x?.alerts ?? []).map((a: string, i: number) => <p key={i} className="text-xs" style={{ color: "var(--verdict-block)" }}>⚠ {a}</p>)}
            <p className="text-xs text-muted">{tr(lang, "근거성 = 1 − D4-01 위험 판정 비율 · 부정 피드백 = D4 판정 이의 / 판정 · 불확실성 미표기 = D4-07 과신 판정 비율", "Groundedness = 1 − share of risky D4-01 verdicts · negative feedback = appeals on D4 verdicts / verdicts · missing uncertainty = share of D4-07 overconfident verdicts")}</p>
          </section>
          <section className="card space-y-2 p-4 text-sm" data-testid="feedback">
            <h2 className="font-semibold">{tr(lang, "④ 사용자 피드백 (이의·라벨)", "④ User feedback (appeals · labels)")}</h2>
            <ul className="text-xs">{(x?.feedback ?? []).length === 0 ? <li className="text-muted">{tr(lang, "없음", "None")}</li> : x.feedback.map((f: any, i: number) => (
              <li key={i}>👎 <Link className="text-primary" href={`/findings/${f.finding}`}>{f.agent}</Link> · {LX(lang, f.reason)} · {LX(lang, f.detail)} · {f.status}{f.label && ` (${f.label})`}</li>))}</ul>
          </section>
        </div>
        <div className="space-y-4">
          <SettingsCard lang={lang} user={user} id="d4-06" showRules title={tr(lang, "② 전파 방지 — 출처 없는 출력 적재 거부(no-provenance → block)", "② Propagation guard — refuse unsourced output (no-provenance → block)")} />
          <SettingsCard lang={lang} user={user} id="d4-07" title={tr(lang, "d4-07 — 저신뢰 기준 · 회귀 허용폭", "d4-07 — low-confidence level · regression tolerance")} />
        </div>
      </div>
    </>
  );
}
