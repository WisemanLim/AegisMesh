// SCR-Q04 SLO·비용·오탐 예산 — 에이전트별 일 오탐 예산(80% 경보·초과 경보 전용·7일 복귀), 임계 조정 제안,
// 골든셋 1만 건 재생(NFR-Q1), 공개 공격 코퍼스 미탐률(NFR-Q2), 판정 이의 현황(SCR-O02).
import Link from "next/link";
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { t, tr, LX, nm } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { enforceBudget, importCorpus, runGolden } from "./actions";

import { L } from "@/lib/i18n";

const ST: Record<string, [string, string]> = { ok: ["정상", "var(--verdict-allow)"], warn: ["80% 경보", "#9d6105"], exceeded: ["초과", "var(--verdict-block)"], alert_only: ["경보 전용", "var(--verdict-block)"] };
const pct = (x: number, d = 1) => `${(x * 100).toFixed(d)}%`;

export default async function Slo({ searchParams }: { searchParams: Promise<{ msg?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const { msg } = await searchParams;
  const [{ data: q }, { data: obs }, { data: gk }] = await Promise.all([safe(api("/v1/quality"), null as any), safe(api("/v1/observability"), null as any),
    safe(api("/v1/quality/garak"), { latest: null } as any)]);
  const gr = gk?.latest;
  if (!q) return <Banner tone="warn">{L(lang, "품질 지표를 불러오지 못함")}</Banner>;
  const b = q.budget, g = q.golden;
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupOpsRt")} › ${t(lang, "slo")}`} title={tr(lang, "SLO · 오탐 예산 · 품질", "SLO · false-positive budget · quality")} />
      {msg && <div className="mb-3"><Banner tone={msg.startsWith(L(lang, "실패")) ? "danger" : "info"}>{L(lang, msg)}</Banner></div>}
      <div className="mb-4 grid grid-cols-5 gap-3 text-sm">
        {obs && ["input", "tool", "output"].map((k) => { const x = obs.slo.gates[k]; return (
          <div key={k} className="card p-3"><div className="text-xs text-muted">{k}{L(lang, " 관문 p95")}</div><div className="text-xl font-bold" style={{ color: x.burn >= 0.9 ? "#9d6105" : undefined }}>{LX(lang, x.p95Ms)}ms</div><div className="text-xs">{L(lang, "예산 ")}{LX(lang, x.budgetMs)}ms · {Math.round(x.burn * 100)}%</div></div>); })}
        <div className="card p-3"><div className="text-xs text-muted">{L(lang, "골든셋 오탐률")}</div><div className="text-xl font-bold">{g ? pct(g.overallFpRate, 3) : "—"}</div><div className="text-xs">{L(lang, "목표 ≤ ")}{pct(q.targets.fpRate)} {g ? L(lang, "· {0}건", g.samples) : ""}</div></div>
        <div className="card p-3" data-testid="corpus-headline"><div className="text-xs text-muted">{tr(lang, "공개 코퍼스 미탐률 (주입·탈옥 · 인라인 엔진)", "Public-corpus miss rate (injection · jailbreak · inline engine)")}</div><div className="text-xl font-bold" style={{ color: q.corpusHeadline && q.corpusHeadline.missRate > q.targets.missRate ? "var(--verdict-block)" : undefined }}>{q.corpusHeadline ? pct(q.corpusHeadline.missRate) : "—"}</div><div className="text-xs">{L(lang, "목표 ≤ ")}{pct(q.targets.missRate, 0)}{q.corpusHeadline ? ` · ${q.corpusHeadline.corpora.map((c: any) => c.name).join(" · ")} · ${q.corpusHeadline.items}` : ""}</div>{q.corpusHeadlineDeep && <div className="text-xs" data-testid="corpus-headline-deep">{tr(lang, "응답 후 깊은 검사 포함 ", "with the post-response deep check ")}<b style={{ color: q.corpusHeadlineDeep.missRate > q.targets.missRate ? "var(--verdict-block)" : undefined }}>{pct(q.corpusHeadlineDeep.missRate)}</b></div>}</div>
      </div>
      <section className="card mb-4 p-4 text-sm" data-testid="fp-budget">
        <h2 className="mb-2 font-semibold">{L(lang, "오탐 예산 (")}{LX(lang, b.day)}{L(lang, ", UTC) — 예산 = max(")}{LX(lang, b.min)}{L(lang, ", 인라인 판정 × ")}{pct(b.rate)}{L(lang, ") · 80% 경보(MSG-008) · 초과 → 경보 전용(차단 안 함) · ")}{LX(lang, b.recoverDays)}{L(lang, "일 오탐률 ≤ ")}{pct(b.rate)}{L(lang, " 이면 복귀")}</h2>
        <table className="grid-table text-xs"><thead><tr><th>{L(lang, "에이전트")}</th><th>{L(lang, "판정")}</th><th>{L(lang, "확정 오탐")}</th><th>{L(lang, "예산")}</th><th>{L(lang, "소진")}</th><th>{L(lang, "상태")}</th><th>{L(lang, "복귀 조건")}</th><th>{L(lang, "임계 조정 제안")}</th></tr></thead>
          <tbody>{b.agents.length === 0 ? <tr><td colSpan={8} className="text-muted">{L(lang, "오늘 인라인 판정·확정 오탐 없음")}</td></tr> : b.agents.slice(0, 30).map((r: any) => (
            <tr key={r.agent}><td><Link className="text-primary" href={`/catalog/${r.agent}`}>{LX(lang, r.agent)}</Link> {nm(lang, r)}</td><td>{LX(lang, r.judged)}</td><td>{LX(lang, r.fp)}</td><td>{LX(lang, r.budget)}</td>
              <td>{Math.round(r.consumed * 100)}%</td><td style={{ color: ST[r.status]?.[1] }}>{L(lang, ST[r.status]?.[0] ?? r.status)}</td>
              <td>{r.recovery ? L(lang, "{0} 이후 · 7일 {1}{2}", fmtTime(r.recovery.after), pct(r.recovery.weekFpRate, 2), r.recovery.met ? " ✓" : "") : "—"}</td>
              <td>{r.suggestion ? <span title={r.suggestion.yaml}>{LX(lang, r.suggestion.item)}{L(lang, " 임계 → ")}<b>{LX(lang, r.suggestion.suggested)}</b>{L(lang, " (오탐 최대 ")}{LX(lang, r.suggestion.fpMaxConfidence)}{L(lang, ", 다른 위험 ")}{LX(lang, r.suggestion.otherRiskBelow)}{L(lang, "건 경보화)")}</span> : "—"}</td></tr>))}</tbody></table>
        {can(user, "quality.run") && <form action={enforceBudget} className="mt-2"><button className="btn btn-secondary h-7 text-xs">{L(lang, "지금 점검 (worker 는 5분마다)")}</button></form>}
      </section>
      <div className="grid grid-cols-2 gap-4">
        <section className="card p-4 text-sm" data-testid="golden">
          <h2 className="mb-2 font-semibold">{L(lang, "골든셋 재생 (NFR-Q1 · 주간)")}</h2>
          {g ? (<>
            <p className="text-xs">{fmtTime(g.at)} · {LX(lang, g.by)}{L(lang, " · 합성 ")}{LX(lang, g.synthetic)}{L(lang, " + 이의 편입 ")}{LX(lang, g.appealSamples)} = {LX(lang, g.samples)}{L(lang, "건 · 에이전트 ")}{LX(lang, g.agents)}{L(lang, "종 · 차단 표본 ")}{LX(lang, g.blockedSamples)} · {LX(lang, g.durationMs)}ms</p>
            <p className="text-xs">{L(lang, "언어별 ")}{Object.entries(g.byLang).map(([k, v]: [string, any]) => tr(lang, `${k} ${v.n}건 ${pct(v.fpRate, 2)}`, `${k} ${v.n} items ${pct(v.fpRate, 2)}`)).join(" · ")}{L(lang, " · 목표 초과 ")}{g.overTarget.length ? g.overTarget.join(", ") : L(lang, "없음")}</p>
            <ul className="mt-2 space-y-1 text-xs">{g.perAgent.filter((r: any) => r.fp).slice(0, 8).map((r: any) => <li key={r.agent}>{LX(lang, r.agent)}{L(lang, " 오탐 ")}{LX(lang, r.fp)}/{LX(lang, r.judged)} ({pct(r.fpRate, 2)}) {JSON.stringify(r.categories)}</li>)}</ul>
            {g.review.length > 0 && <details className="mt-2 text-xs"><summary>{L(lang, "수동 검수 표본 ")}{g.review.length}{L(lang, "건")}</summary><ul className="mt-1 space-y-1">{g.review.map((x: any) => <li key={x.id} className="mono">{x.id} {LX(lang, x.gate)}/{LX(lang, x.category)} → {LX(lang, x.agent)} {LX(lang, x.verdict)} · {LX(lang, x.preview)}</li>)}</ul></details>}
          </>) : <p className="text-xs text-muted">{L(lang, "아직 재생 기록 없음")}</p>}
          {can(user, "quality.run") && <form action={runGolden} className="mt-2"><button className="btn btn-primary h-8 text-xs">{L(lang, "1만 건 지금 재생")}</button></form>}
        </section>
        <section className="card p-4 text-sm" data-testid="corpora">
          <h2 className="mb-2 font-semibold">{L(lang, "공개 공격 코퍼스 미탐률 (NFR-Q2 · 목표 ≤ 10%)")}</h2>
          <p className="mb-2 text-xs text-muted">{tr(lang, "규칙 전용 = 분류기를 끈 엔진 · 이중 = 배포 기본(규칙 + 분류기). 유해 요청(기법 없음)은 D1 탐지 대상 밖이라 참고값. 정상 코퍼스는 오탐률.", "Rules only = engine with the classifier off · dual = deployed default (rules + classifier). Plain harmful requests (no technique) are outside D1 detection and shown for reference. Benign corpora show the false-positive rate.")}</p>
          {q.corpora.length === 0 ? <p className="text-xs text-muted">{L(lang, "반입 기록 없음")}</p> : (
            <table className="grid-table text-xs" data-testid="corpus-table"><thead><tr><th>{tr(lang, "코퍼스", "Corpus")}</th><th>{tr(lang, "종류", "Kind")}</th><th>{tr(lang, "엔진", "Engine")}</th><th>{tr(lang, "배치", "Placement")}</th><th>{tr(lang, "건수", "Items")}</th><th>{tr(lang, "미탐·오탐", "Miss · FP")}</th><th>{tr(lang, "범주(상위)", "Top categories")}</th><th>{tr(lang, "출처", "Source")}</th></tr></thead>
              <tbody>{q.corpora.map((c: any) => {
                const benign = c.kind === "benign";
                const rate = benign ? c.fpRate : c.missRate;
                const bad = c.ok === false;
                return (<tr key={c.seq}><td><b>{c.name.split("·")[0]}</b></td>
                  <td>{benign ? tr(lang, "정상", "benign") : c.scope === "harmful-request" ? tr(lang, "유해 요청(참고)", "harmful request (ref.)") : tr(lang, "주입·탈옥", "injection")}</td>
                  <td>{c.variant === "rules-only" ? tr(lang, "규칙 전용", "rules only") : c.variant === "deep" ? tr(lang, "깊은 검사", "deep check") : tr(lang, "이중", "dual")}</td><td>{c.mode === "indirect" ? tr(lang, "간접", "indirect") : c.mode === "both" ? tr(lang, "둘 다", "both") : tr(lang, "직접", "direct")}</td>
                  <td>{c.items}</td><td style={{ color: bad ? "var(--verdict-block)" : c.ok ? "var(--verdict-allow)" : undefined }}>{benign ? "FP " : ""}{pct(rate)}</td>
                  <td className="text-muted">{c.byCategory.slice(0, 3).map((x: any) => `${x.category} ${pct(benign ? x.fpRate : x.missRate, 0)}`).join(" · ")}</td>
                  <td className="mono" data-user>{c.source || "—"} · {c.license || "—"}</td></tr>);
              })}</tbody></table>)}
          {can(user, "redteam") ? (
            <form action={importCorpus} className="mt-3 grid grid-cols-2 gap-2 text-xs">
              <label className="col-span-2">{L(lang, "파일 (JSONL·CSV — JailbreakBench·HarmBench·garak 형식, 프롬프트 열 자동 인식)")}<input type="file" name="file" accept=".jsonl,.json,.csv" className="mt-1 block w-full" /></label>
              <label>{L(lang, "이름")}<input name="name" className="input mt-1 w-full" /></label>
              <label>{L(lang, "방식")}<select name="mode" className="input mt-1 w-full"><option value="direct">{L(lang, "직접 입력")}</option><option value="indirect">{L(lang, "간접(검색 문서)")}</option><option value="both">{L(lang, "둘 다")}</option></select></label>
              <label>{tr(lang, "종류", "Kind")}<select name="kind" className="input mt-1 w-full"><option value="attack">{tr(lang, "공격(미탐률)", "attack (miss rate)")}</option><option value="benign">{tr(lang, "정상(오탐률)", "benign (false-positive rate)")}</option></select></label>
              <label>{L(lang, "출처")}<input name="source" className="input mt-1 w-full" placeholder={L(lang, "내부 미러 경로")} /></label>
              <label>{L(lang, "라이선스")}<input name="license" className="input mt-1 w-full" placeholder="MIT · CC-BY-4.0 …" /></label>
              <button className="btn btn-primary col-span-2 h-8 justify-center">{L(lang, "반입·재생 (페이로드는 저장하지 않음)")}</button>
            </form>
          ) : <p className="mt-2 text-xs text-muted">{L(lang, "코퍼스 반입은 레드팀 권한 (공격 자산 분리, §13.1)")}</p>}
        </section>
      </div>
      <section className="card mt-4 p-4 text-sm" data-testid="garak">
        <h2 className="mb-2 font-semibold">{tr(lang, "외부 레드팀 엔진 garak — 무방비 모델 대비 관문 뒤 공격 성공률", "External red-team engine garak — attack success rate behind the gates vs an unprotected model")}</h2>
        {!gr ? <p className="text-xs text-muted">{tr(lang, "실행 기록 없음 — make garak-scan", "No run yet — make garak-scan")}</p> : (
          <>
            <p className="mb-2 text-xs">garak {gr.garakVersion} · {tr(lang, "대상", "target")} {gr.target} ({gr.profile}) · {fmtTime(gr.at)} · {tr(lang, "무방비", "unprotected")} <b>{pct(gr.baseline.asr)}</b> → {tr(lang, "관문 뒤", "behind the gates")} <b>{pct(gr.guarded.asr)}</b> ({gr.guarded.hits}/{gr.guarded.total})</p>
            <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "탐침", "Probe")}</th><th>{tr(lang, "탐지기", "Detector")}</th><th>{tr(lang, "시도", "Attempts")}</th><th>{tr(lang, "무방비 ASR", "Unprotected ASR")}</th><th>{tr(lang, "관문 ASR", "Guarded ASR")}</th></tr></thead>
              <tbody>{gr.probes.map((x: any) => (<tr key={`${x.probe}|${x.detector}`}><td className="mono">{x.probe}</td><td className="mono">{x.detector}</td><td>{x.guarded.total}</td>
                <td>{pct(x.baseline.asr)}</td><td style={{ color: x.guarded.asr > 0.1 ? "var(--verdict-block)" : undefined }}>{pct(x.guarded.asr)}</td></tr>))}</tbody></table>
          </>)}
      </section>
      <section className="card mt-4 p-4 text-sm" data-testid="appeals">
        <h2 className="mb-2 font-semibold">{L(lang, "판정 이의 (SCR-O02) — 접수 ")}{LX(lang, q.appeals.received)}{L(lang, " · 오탐 확정 ")}{LX(lang, q.appeals.fp)}{L(lang, " · 정탐 유지 ")}{LX(lang, q.appeals.tp)}</h2>
        <ul className="space-y-1 text-xs">{q.appeals.recent.slice(0, 10).map((x: any) => (
          <li key={x.id}><Link className="text-primary" href={`/findings/${x.findingId}`}>{LX(lang, x.findingId)}</Link> {LX(lang, x.agent)} {LX(lang, x.verdict)} · {LX(lang, x.reasonTitle)} · <Chip>{x.status === "decided" ? (x.label === "fp" ? L(lang, "오탐 확정") : L(lang, "정탐 유지")) : L(lang, "접수")}</Chip> {LX(lang, x.requestedBy)} {fmtTime(x.requestedAt)}</li>))}</ul>
      </section>
    </>
  );
}
