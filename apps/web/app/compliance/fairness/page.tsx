// SCR-N06 공정성·윤리 지표 — 집단별 차단율(가명·집계)·성능 분해(오탐·미탐 격차)·영향 평가 문서·공개 설정. 한도 초과 = 경보 + 위험 등록부(MSG-023).
import Link from "next/link";
import { Banner, Chip, Kpi } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { t as tk, tr } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { measureNow, saveAssessment, saveDisclosure } from "../actions";

const AX: Record<string, [string, string]> = { age: ["연령", "Age"], lang: ["언어", "Language"], region: ["지역", "Region"], channel: ["채널", "Channel"] };
const ST: Record<string, [string, string, string]> = { approved: ["승인", "Approved", "var(--verdict-allow)"], draft: ["초안", "Draft", "var(--sev-info)"],
  "needs-update": ["갱신 필요", "Needs update", "#9d6105"], missing: ["없음", "Missing", "var(--verdict-block)"] };
const pct = (x?: number | null) => (x == null ? "—" : `${(x * 100).toFixed(2)}%`);

export default async function Fairness({ searchParams }: { searchParams: Promise<{ target?: string; days?: string; msg?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const sp = await searchParams;
  const days = Number(sp.days || 7);
  const q = new URLSearchParams({ days: String(days), ...(sp.target ? { target: sp.target } : {}) });
  const { data: v, error } = await safe(api(`/v1/compliance/fairness?${q}`), null as any);
  const write = can(user, "compliance.write");
  if (!v) return <><PageHeader crumb={tk(lang, "groupGov")} title={tr(lang, "공정성·윤리 지표", "Fairness & ethics")} /><p className="text-sm text-red-600">{error}</p></>;
  const lim = Number(v.limits.maxGapPp ?? 1.5);
  const minN = Number(v.limits.minGroupSize ?? 30);
  const gaps = Object.entries(v.live.gaps as Record<string, any>);
  const worst = gaps.sort((a, b) => b[1].gapPp - a[1].gapPp)[0];
  const axes = [...new Set((v.live.blockRates as any[]).map((r) => r.axis))];
  const maxRate = Math.max(0.0001, ...(v.live.blockRates as any[]).filter((r) => r.n >= minN).map((r) => r.rate));
  const axL = (a: string) => (AX[a] ? tr(lang, ...AX[a]) : a);
  return (
    <>
      <PageHeader crumb={`${tk(lang, "groupGov")} › ${tr(lang, "컴플라이언스", "Compliance")} › ${tr(lang, "공정성", "Fairness")}`} title={tr(lang, "공정성·윤리 지표", "Fairness & ethics metrics")}
        actions={write ? <form action={measureNow}><input type="hidden" name="target" value={sp.target ?? ""} /><input type="hidden" name="days" value={days} />
          <button className="btn btn-primary" data-testid="measure">{tr(lang, "지금 측정", "Measure now")}</button></form> : undefined} />
      {sp.msg && <div className="mb-3"><Banner tone={/^(실패|Failed)/.test(sp.msg) ? "danger" : /초과|over the limit/.test(sp.msg) ? "warn" : "info"}>{sp.msg}</Banner></div>}
      <form className="card mb-4 flex flex-wrap items-center gap-3 p-3 text-sm" data-testid="filters">
        <label>{tr(lang, "대상", "Target")} <select name="target" defaultValue={sp.target ?? ""} className="input ml-1 h-8">
          <option value="">{tr(lang, "전체", "All")}</option>{v.targets.map((x: string) => <option key={x} value={x}>{x}</option>)}</select></label>
        <label>{tr(lang, "기간", "Period")} <select name="days" defaultValue={String(days)} className="input ml-1 h-8">
          {[1, 7, 30, 90].map((d) => <option key={d} value={d}>{tr(lang, `${d}일`, `${d} d`)}</option>)}</select></label>
        <button className="btn btn-secondary h-8">{tr(lang, "보기", "View")}</button>
        <span className="text-xs text-muted">{tr(lang, `정례 측정 주 1회 · 판정 ${v.live.records}건 · 집단 속성은 가명·집계만(개인 식별 없음)`, `Weekly scheduled measurement · ${v.live.records} records · group attributes are pseudonymous aggregates only`)}</span>
      </form>
      <div className="mb-4 grid grid-cols-3 gap-3" data-testid="kpis">
        <Kpi label={tr(lang, "측정 집단", "Groups measured")} value={`${axes.length}${tr(lang, "축", " axes")} ${(v.live.blockRates as any[]).filter((r) => r.n >= minN).length}${tr(lang, "개", "")}`}
          sub={axes.map(axL).join(" · ") || "—"} accent="var(--primary)" />
        <Kpi label={tr(lang, "최대 차단율 격차", "Max block-rate gap")} value={worst ? `${worst[1].gapPp.toFixed(2)}%p` : "—"}
          sub={worst ? tr(lang, `${axL(worst[0])} · ${worst[1].hi} · 한도 ${lim}%p${worst[1].gapPp > lim ? " 초과" : ""}`, `${axL(worst[0])} · ${worst[1].hi} · limit ${lim}pp${worst[1].gapPp > lim ? " exceeded" : ""}`) : tr(lang, `한도 ${lim}%p`, `limit ${lim}pp`)}
          accent={worst && worst[1].gapPp > lim ? "var(--verdict-block)" : "var(--verdict-allow)"} />
        <Kpi label={tr(lang, "영향 평가 최신", "Impact assessments current")} value={`${v.assessmentFresh}/${v.assessments.length}`}
          sub={v.assessments.filter((a: any) => a.status !== "approved").map((a: any) => a.target).join(" · ") || "—"} accent={v.assessmentFresh < v.assessments.length ? "#9d6105" : "var(--verdict-allow)"} />
      </div>
      {v.latest?.over && Object.keys(v.latest.over).length > 0 && (
        <div className="mb-4" data-testid="over-warning"><Banner tone="warn">
          {tr(lang, `한도 초과 (${fmtTime(v.latest.at)}) — ${Object.entries(v.latest.over).map(([ax, g]: [string, any]) => `${axL(ax)} ${g.gapPp.toFixed(2)}%p (${g.hi})`).join(", ")} · 경보 · 위험 등록부 자동 등록 `,
            `Over the limit (${fmtTime(v.latest.at)}) — ${Object.entries(v.latest.over).map(([ax, g]: [string, any]) => `${axL(ax)} ${g.gapPp.toFixed(2)}pp (${g.hi})`).join(", ")} · alert · auto-registered risk `)}
          {v.latest.risk && <Link className="font-semibold underline" href="/risks">{v.latest.risk}</Link>}
          {tr(lang, " · 이의 신청 재판정 결과는 골든셋에 편입 (MSG-023)", " · appeal re-judgements are added to the golden set (MSG-023)")}</Banner></div>
      )}
      <div className="grid grid-cols-[1fr_1fr] gap-4">
        <section className="card p-4 text-sm" data-testid="block-rates">
          <h2 className="mb-2 font-semibold">{tr(lang, `집단별 차단율 (${days}일 판정 기준)`, `Block rate by group (${days}-day verdicts)`)}</h2>
          {axes.length === 0 ? <p className="text-xs text-muted">{tr(lang, "집단 라벨이 있는 판정 없음 — 게이트웨이가 subject.groups(가명 범주)를 실어 보내거나, 문자 체계(lang) 기본 축", "No labelled verdicts — the gateway sends subject.groups (pseudonymous categories); the script-based lang axis is the default")}</p>
            : axes.map((ax) => {
              const g = v.live.gaps[ax];
              const over = g && g.gapPp > lim;
              return (
                <div key={ax} className="mb-3">
                  <div className="mb-1 text-xs font-semibold">{axL(ax)} {g ? <span style={{ color: over ? "var(--verdict-block)" : undefined }}>· {tr(lang, "격차", "gap")} {g.gapPp.toFixed(2)}%p{over ? tr(lang, " — 한도 초과", " — over limit") : ""}</span> : <span className="text-muted">· {tr(lang, "비교 불가(표본 부족·단일 집단)", "not comparable (small sample · single group)")}</span>}</div>
                  {(v.live.blockRates as any[]).filter((r) => r.axis === ax).map((r) => {
                    const small = r.n < minN;
                    const hot = over && r.group === g.hi;
                    return (
                      <div key={r.group} className="flex items-center gap-2 text-xs">
                        <span className="w-20 truncate">{r.group}</span>
                        <div className="h-3 flex-1 rounded bg-line"><div className="h-3 rounded" style={{ width: `${Math.max(1, (r.rate / maxRate) * 100)}%`, background: hot ? "var(--verdict-block)" : small ? "var(--sev-info)" : "var(--primary)" }} /></div>
                        <span className="w-28 text-right">{pct(r.rate)} <span className="text-muted">n={r.n}{small ? "*" : ""}</span>{hot ? <b style={{ color: "var(--verdict-block)" }}> {tr(lang, "초과", "over")}</b> : null}</span>
                      </div>
                    );
                  })}
                </div>
              );
            })}
          <p className="text-[11px] text-muted">{tr(lang, `* 표본 ${minN} 미만 — 비교에서 제외 · 한도 ${lim}%p (정책 agentParams.d10-05)`, `* fewer than ${minN} samples — excluded · limit ${lim}pp (policy agentParams.d10-05)`)}</p>
        </section>
        <section className="card p-4 text-sm" data-testid="perf">
          <h2 className="mb-2 font-semibold">{tr(lang, "성능 분해 · 격차 지표 (레드팀 코퍼스 — 라벨 있음)", "Performance breakdown · gap metrics (red-team corpus — labelled)")}</h2>
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "집단", "Group")}</th><th>{tr(lang, "표본", "Samples")}</th><th>{tr(lang, "오탐률", "FP rate")}</th><th>{tr(lang, "미탐률", "Miss rate")}</th><th>{tr(lang, "격차", "Gap")}</th></tr></thead>
            <tbody>{v.perf.length === 0 ? <tr><td colSpan={5} className="text-muted">{tr(lang, "캠페인 없음 — 레드팀 실행", "No campaign — run red team")}</td></tr> : v.perf.map((g: any) => (
              <tr key={g.group}><td>{g.group}</td><td>{g.n}</td><td>{pct(g.fpr)}</td><td>{pct(g.missRate)}</td><td>{g.gapPp == null ? "—" : g.gapPp === 0 ? tr(lang, "기준", "baseline") : `+${g.gapPp.toFixed(2)}`}</td></tr>))}</tbody></table>
          <p className="mt-1 text-[11px] text-muted">{tr(lang, `오탐률 배율 한도 ${v.limits.maxRatio} · 탐지율 비 0.8(4/5 규칙) · fairlearn MetricFrame 방식 집단 분해`, `FP-rate ratio limit ${v.limits.maxRatio} · detection ratio 0.8 (4/5 rule) · fairlearn MetricFrame-style breakdown`)}</p>
          <h3 className="mb-1 mt-3 text-xs font-semibold">{tr(lang, "추세 — 최대 격차", "Trend — max gap")}</h3>
          <div className="flex items-end gap-1" data-testid="trend">{v.trend.length === 0 ? <span className="text-xs text-muted">—</span> : v.trend.map((x: any) => (
            <div key={x.seq} title={`${fmtTime(x.at)} · ${x.maxGapPp.toFixed(2)}%p · ${x.verdict}`} className="w-4 rounded-t"
              style={{ height: `${Math.min(64, 6 + x.maxGapPp * 10)}px`, background: x.maxGapPp > lim ? "var(--verdict-block)" : "var(--primary)" }} />))}</div>
        </section>
      </div>
      <div className="mt-4 grid grid-cols-[1fr_360px] gap-4">
        <section className="card p-4 text-sm" data-testid="assessments">
          <h2 className="mb-2 font-semibold">{tr(lang, "영향 평가 문서", "Impact assessments")}</h2>
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "대상", "Target")}</th><th>{tr(lang, "최근 평가", "Last review")}</th><th className="whitespace-nowrap">{tr(lang, "상태", "Status")}</th><th>{tr(lang, "요약", "Summary")}</th></tr></thead>
            <tbody>{v.assessments.length === 0 ? <tr><td colSpan={4} className="text-muted">{tr(lang, "보호 대상 없음", "No protected targets")}</td></tr> : v.assessments.map((a: any) => (
              <tr key={a.target}><td className="mono whitespace-nowrap">{a.target}</td><td>{a.reviewedAt ? `${fmtTime(a.reviewedAt)} · ${a.by}` : "—"}</td>
                <td className="whitespace-nowrap"><b style={{ color: ST[a.status]?.[2] }}>{tr(lang, ...(ST[a.status] ?? [a.status, a.status, ""]).slice(0, 2) as [string, string])}</b>{a.fairnessAlertAt && a.status === "needs-update" ? <span className="text-muted"> · {tr(lang, "이후 한도 초과", "limit exceeded since")}</span> : null}</td>
                <td className="max-w-[320px] truncate" title={a.summary ?? ""}>{a.summary ?? "—"}</td></tr>))}</tbody></table>
          {write && v.targets.length > 0 && (
            <form action={saveAssessment} className="mt-3 flex flex-wrap items-center gap-2" data-testid="assessment-form">
              <input type="hidden" name="target" value={sp.target ?? ""} /><input type="hidden" name="days" value={days} />
              <select name="assessTarget" className="input h-8 text-xs" aria-label="assessment target" defaultValue={sp.target || v.targets[0]}>{v.targets.map((x: string) => <option key={x} value={x}>{x}</option>)}</select>
              <input name="summary" required className="input h-8 flex-1 text-xs" placeholder={tr(lang, "평가 요약 — 영향·완화·잔여 위험", "Summary — impact · mitigation · residual risk")} aria-label="assessment summary" />
              <select name="status" className="input h-8 text-xs" aria-label="assessment status"><option value="approved">{tr(lang, "승인", "Approved")}</option><option value="draft">{tr(lang, "초안", "Draft")}</option></select>
              <button className="btn btn-secondary h-8 text-xs">{tr(lang, "평가 기록", "Record")}</button>
            </form>
          )}
        </section>
        <section className="card p-4 text-sm" data-testid="disclosure">
          <h2 className="mb-2 font-semibold">{tr(lang, "격차 지표 공개", "Gap metric disclosure")}</h2>
          <form action={saveDisclosure} className="space-y-2 text-xs">
            <input type="hidden" name="target" value={sp.target ?? ""} /><input type="hidden" name="days" value={days} />
            <label className="flex items-center gap-2"><input type="checkbox" name="internal" defaultChecked={v.disclosure.internal} disabled={!write} />{tr(lang, "내부 공개", "Internal")}</label>
            <label className="flex items-center gap-2"><input type="checkbox" name="external" defaultChecked={v.disclosure.external} disabled={!write} />{tr(lang, "외부 이해관계자 공개 (투명성 카드 연동)", "External stakeholders (via transparency cards)")}</label>
            {write && <button className="btn btn-secondary h-7 text-xs">{tr(lang, "저장", "Save")}</button>}
            <p className="text-muted">{v.disclosure.at ? `${fmtTime(v.disclosure.at)} · ${v.disclosure.by}` : tr(lang, "기본값 — 내부만", "Default — internal only")} · <Link className="text-primary" href="/compliance/cards">{tr(lang, "시스템·모델 카드 ›", "System & model cards ›")}</Link></p>
          </form>
          <div className="mt-2 flex flex-wrap gap-1 text-[11px]"><Chip>NIST AI RMF MEASURE 2.11</Chip><Chip>ISO/IEC 42001 A.5</Chip></div>
        </section>
      </div>
    </>
  );
}
