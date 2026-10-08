// SCR-O02 판정 상세·이의 제기 — 근거 뷰(CMP-08)·표준 칩·원장 레코드·이의 신청·재판정·신뢰 지표.
import { notFound } from "next/navigation";
import { Banner, Chip, SeverityBadge, VerdictBadge } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { ApiError, api, safe } from "@/lib/api";
import { fmtTime, shortHash, standardChips } from "@/lib/format";
import { can, me } from "@/lib/session";
import { appealFinding, decideAppeal } from "../actions";

import { L, LX } from "@/lib/i18n";
import { prefs } from "@/lib/session";

const SAMPLE: Record<string, string> = { input: '{"text": "마스킹한 입력"}', output: '{"output": "마스킹한 출력"}', tool: '{"tool": {"name": "도구", "args": {}}}' };

export default async function FindingDetail({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<{ msg?: string }> }) {
  const { lang } = await prefs();
  const { id } = await params;
  const { msg } = await searchParams;
  let f: any;
  try {
    f = await api(`/v1/findings/${id}`);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound();
    throw e;
  }
  const user = await me();
  const { data: ap } = await safe(api(`/v1/findings/${id}/appeals`), { items: [] as any[], trust: null as any });
  const open = ap.items.find((x: any) => x.status === "received");
  const risky = (f.effectiveVerdict ?? f.verdict) !== "allow" || f.verdict !== "allow";
  return (
    <>
      <PageHeader crumb={L(lang, "판정 › 상세")} title={f.ruleId} />
      {msg && <div className="mb-3"><Banner tone={msg.startsWith(L(lang, "실패")) ? "danger" : "info"}>{L(lang, msg)}</Banner></div>}
      <div className="grid grid-cols-3 gap-4">
        <section className="card col-span-2 p-4 text-sm">
          <div className="flex items-center gap-2">
            <VerdictBadge v={f.verdict} />
            {f.effectiveVerdict && <>{L(lang, "→ 유효 ")}<VerdictBadge v={f.effectiveVerdict} /></>}
            <SeverityBadge s={f.severity} /> <span>{L(lang, "신뢰도 ")}{LX(lang, f.confidence)}</span>
            {!f.valid && <Chip>{L(lang, "무효(근거 없음)")}</Chip>}{f.degraded && <Chip>{L(lang, "강등")}</Chip>}
          </div>
          <p className="mt-3">{(lang === "en" && f.ruleDescriptionEn) || LX(lang, f.ruleDescription ?? "—")}</p>
          <h2 className="mb-2 mt-4 font-semibold">{L(lang, "근거 (evidence)")}</h2>
          <table className="grid-table"><thead><tr><th>{L(lang, "유형")}</th><th>{L(lang, "위치")}</th><th>{L(lang, "범위")}</th><th>{L(lang, "설명")}</th></tr></thead><tbody>
            {f.evidence.map((e: any, i: number) => (
              <tr key={i}><td>{LX(lang, e.kind)}</td><td className="mono">{LX(lang, e.location ?? "—")}</td><td className="mono">{e.offset != null ? `${e.offset}+${e.length}` : "—"}</td><td>{LX(lang, e.note)}</td></tr>
            ))}
          </tbody></table>
          <p className="mt-2 rounded bg-[#f3f4f8] px-3 py-2 text-xs text-muted">{L(lang, "원문 미보존 (NFR-D1) — payloadRef: ")}{String(f.payloadRef)}{f.action?.transformApplied ? L(lang, " · 무해화 결과는 응답에만 전달되고 저장되지 않음") : ""}</p>
        </section>
        <aside className="space-y-4">
          <section className="card p-4 text-sm">
            <dl className="grid grid-cols-[90px_1fr] gap-y-1">
              <dt className="text-muted">{L(lang, "에이전트")}</dt><dd>{f.agent.id} v{LX(lang, f.agent.version)} · {LX(lang, f.agent.engine)}</dd>
              <dt className="text-muted">{L(lang, "관문")}</dt><dd>{LX(lang, f.gate)}</dd>
              <dt className="text-muted">{L(lang, "지연")}</dt><dd>{LX(lang, f.latencyMs)}ms</dd>
              <dt className="text-muted">{L(lang, "테넌트")}</dt><dd>{LX(lang, f.subject.tenant)}</dd>
              <dt className="text-muted">{L(lang, "시각")}</dt><dd>{fmtTime(f.occurredAt)}</dd>
              <dt className="text-muted">trace</dt><dd className="mono break-all">{LX(lang, f.traceId)}</dd>
            </dl>
            <div className="mt-2 flex flex-wrap gap-1">{standardChips(f.standards).map((s) => <Chip key={s}>{s}</Chip>)}</div>
          </section>
          <section className="card p-4 text-sm">
            <h2 className="mb-2 font-semibold">{L(lang, "원장 레코드")}</h2>
            {f.ledger ? (
              <dl className="grid grid-cols-[70px_1fr] gap-y-1 mono">
                <dt>seq</dt><dd>{f.ledger.seq}</dd><dt>hash</dt><dd>{shortHash(f.ledger.hash, 16)}</dd><dt>prev</dt><dd>{shortHash(f.ledger.prevHash, 16)}</dd>
              </dl>
            ) : "—"}
          </section>
        </aside>
      </div>
      <div className="mt-4 grid grid-cols-3 gap-4" data-testid="appeal">
        <section className="card col-span-2 space-y-3 p-4 text-sm">
          <h2 className="font-semibold">{L(lang, "이의 신청 · 재판정 ")}<span className="text-xs text-muted">{L(lang, "접수 → 재판정 → 결정(다른 사람) → 오탐이면 골든셋 편입")}</span></h2>
          {ap.items.map((x: any) => (
            <div key={x.id} className="rounded border border-line p-3 text-xs">
              <div className="flex items-center gap-2"><b>{x.id}</b><Chip>{LX(lang, x.reasonTitle)}</Chip><Chip>{LX(lang, x.methodTitle)}</Chip>
                <Chip tone={x.status === "decided" ? "primary" : "default"}>{x.status === "decided" ? (x.label === "fp" ? L(lang, "오탐 확정") : L(lang, "정탐 유지")) : L(lang, "접수")}</Chip>
                <span className="text-muted">{LX(lang, x.requestedBy)} · {fmtTime(x.requestedAt)}{x.decidedBy ? ` → ${x.decidedBy} ${fmtTime(x.decidedAt)}` : ""}</span></div>
              {x.detail && <p className="mt-1" data-user>{x.detail}</p>}
              {x.rejudge?.agent && <p className="mt-1">{L(lang, "교차 재판정(재현 표본) — ")}{f.agent.id} v{LX(lang, x.rejudge.version)}: <b>{LX(lang, x.rejudge.agent.verdict)}</b>{x.rejudge.reproduced ? L(lang, " (재현됨)") : L(lang, " (재현 안 됨)")}{L(lang, " · 같은 계열 ")}{x.rejudge.peers.map((p: any) => `${p.agent}:${p.verdict}`).join(", ") || L(lang, "없음")}{L(lang, " · 합의 ")}{LX(lang, x.rejudge.consensus)}</p>}
              {x.sampleId && <p className="mt-1">{L(lang, "골든셋 편입 ")}{LX(lang, x.sampleId)}</p>}{x.note && <p className="mt-1 text-muted">{L(lang, "결정 메모: ")}<span data-user>{x.note}</span></p>}
              {x.status === "received" && can(user, "quality") && user?.username !== x.requestedBy && (
                <form action={decideAppeal} className="mt-2 flex items-center gap-2">
                  <input type="hidden" name="appeal" value={x.id} /><input type="hidden" name="finding" value={id} />
                  <input name="note" placeholder={L(lang, "결정 메모")} className="input h-7 w-56" />
                  <button name="label" value="fp" className="btn btn-primary h-7 text-xs">{L(lang, "오탐 확정")}</button>
                  <button name="label" value="tp" className="btn btn-secondary h-7 text-xs">{L(lang, "정탐 유지")}</button>
                </form>
              )}
              {x.status === "received" && user?.username === x.requestedBy && <p className="mt-1 text-muted">{L(lang, "본인이 신청한 이의는 다른 사람이 결정한다 (2인)")}</p>}
            </div>
          ))}
          {!open && risky && can(user, "quality") && (
            <form action={appealFinding} className="grid grid-cols-2 gap-2 text-xs">
              <input type="hidden" name="id" value={id} />
              <label>{L(lang, "사유")}<select name="reason" className="input mt-1 w-full"><option value="false_positive">{L(lang, "오탐(정상 요청)")}</option><option value="wrong_rule">{L(lang, "규칙·범주 오분류")}</option><option value="other">{L(lang, "기타")}</option></select></label>
              <label>{L(lang, "재판정 방식")}<select name="method" className="input mt-1 w-full"><option value="rejudge">{L(lang, "사람 검토 + 교차 재판정(재현 표본)")}</option><option value="human">{L(lang, "사람 검토")}</option></select></label>
              <label className="col-span-2">{L(lang, "설명")}<textarea name="detail" rows={2} className="input mt-1 w-full" placeholder={L(lang, "왜 오탐인지 — 업무 맥락")} /></label>
              <label className="col-span-2">{L(lang, "재현 표본 (직접 마스킹한 JSON — 원문은 저장되지 않으므로 교차 재판정·골든셋 편입에만 쓰임)")}<textarea name="sample" rows={2} className="input mono mt-1 w-full" placeholder={L(lang, SAMPLE[f.gate] ?? SAMPLE.input)} /></label>
              <button className="btn btn-primary col-span-2 h-8 justify-center">{L(lang, "이의 신청")}</button>
            </form>
          )}
          {!risky && <p className="text-xs text-muted">{L(lang, "allow 판정은 오탐 이의 대상이 아니다.")}</p>}
        </section>
        <section className="card p-4 text-sm" data-testid="trust">
          <h2 className="mb-2 font-semibold">{L(lang, "신뢰 지표 · ")}{f.agent.id}</h2>
          {ap.trust ? (
            <ul className="space-y-1 text-xs">
              <li>{L(lang, "이의율 ")}{LX(lang, ap.trust.days)}{L(lang, "일 ")}{(ap.trust.appealRate * 100).toFixed(1)}% ({LX(lang, ap.trust.appeals)}{L(lang, " / 위험 판정 ")}{LX(lang, ap.trust.riskyVerdicts)})</li>
              <li>{L(lang, "오탐 확정 추이 ")}{Object.entries(ap.trust.fpTrend).map(([d, n]) => `${d.slice(5)}:${n}`).join(" · ") || L(lang, "없음")}</li>
              <li><a className="text-primary" href="/observability/slo">{L(lang, "오탐 예산·골든셋·코퍼스 →")}</a></li>
            </ul>
          ) : <p className="text-xs text-muted">—</p>}
        </section>
      </div>
    </>
  );
}
