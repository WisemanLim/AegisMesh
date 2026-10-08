// SCR-O06 승인 결정(2인 승인) — 요청 행동·근거, 지출 상한 막대, 보상 경로, 2인 승인 진행, 신뢰 악용 검사, 결정 사유(필수).
import Link from "next/link";
import { notFound } from "next/navigation";
import { Banner, Chip, VerdictBadge } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { ApiError, api } from "@/lib/api";
import { fmtTime, shortHash } from "@/lib/format";
import { sumL, t as tk, tr } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { approve, reject } from "../actions";

const won = (n?: number | null) => (n == null ? "—" : `₩${Math.round(n).toLocaleString("ko-KR")}`);

export default async function ApprovalDecision({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<{ msg?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const { id } = await params;
  const { msg } = await searchParams;
  let c: any;
  try {
    c = await api(`/v1/approvals/${encodeURIComponent(id)}/context`);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound();
    throw e;
  }
  const a = c.approval;
  const who = user?.username ?? "";
  const yes = a.decisions.filter((d: any) => d.decision === "approve");
  const own = a.requestedBy === who;
  const already = a.decisions.some((d: any) => d.principal === who);
  const left = a.expiresAt ? Math.round((new Date(a.expiresAt).getTime() - Date.now()) / 60000) : null;
  const sp = c.spend;
  const over = !!sp?.overLimit;
  const block = !can(user, "approve") ? tk(lang, "readOnly") : own ? tr(lang, "본인이 요청한 행동은 승인할 수 없다 (MSG-011)", "You cannot approve your own request (MSG-011)")
    : already ? tr(lang, "이미 결정함 — 두 번째 승인자는 다른 사람이어야 한다", "Already decided — the second approver must be someone else") : a.status !== "pending" ? tr(lang, `종결됨 (${a.status})`, `Closed (${a.status})`) : "";
  const pct = (n: number) => `${Math.min(100, Math.max(0, n * 100)).toFixed(1)}%`;
  const act = c.action;
  return (
    <>
      <PageHeader crumb={`${tk(lang, "groupOps")} › ${tk(lang, "approvals")} › ${a.id}`} title={tr(lang, `승인 결정 — ${a.id}`, `Approval decision — ${a.id}`)}
        actions={<Link className="btn btn-secondary" href="/approvals">✕ {tr(lang, "닫기", "Close")}</Link>} />
      {msg && <div className="mb-3"><Banner tone={/^(실패|Failed)/.test(msg) ? "danger" : "info"}>{msg}</Banner></div>}
      <div className="card mb-4 flex flex-wrap items-center gap-2 p-3 text-sm" data-testid="verdict-line">
        <VerdictBadge v="require_approval" />
        {c.irreversible && <Chip>{tr(lang, "되돌릴 수 없음", "Irreversible")}</Chip>}
        <Chip tone="primary">{tr(lang, `${a.required}인 승인`, `${a.required}-person approval`)}</Chip>
        <span className="font-semibold">{sumL(lang, a.summary)}</span>
        <span className="ml-auto text-xs" style={{ color: left != null && left < 30 ? "var(--verdict-block)" : undefined }}>
          {a.expiresAt ? tr(lang, `만료 ${fmtTime(a.expiresAt)} (${left! > 0 ? `${left}분 남음` : "만료됨"}) · 만료 시 자동 거절`, `Expires ${fmtTime(a.expiresAt)} (${left! > 0 ? `${left} min left` : "expired"}) · auto-reject on expiry`) : tr(lang, "만료 없음", "No expiry")}</span>
      </div>
      <div className="grid grid-cols-[1fr_1fr] gap-4">
        <div className="space-y-4">
          <section className="card p-4 text-sm" data-testid="request">
            <h2 className="mb-2 font-semibold">{tr(lang, "요청 행동 · 근거", "Requested action · basis")}</h2>
            <table className="grid-table text-xs"><tbody>
              <tr><td className="w-44 text-muted">{tr(lang, "에이전트(주체)", "Agent (principal)")}</td><td className="mono">{c.principal ?? a.requestedBy}</td></tr>
              <tr><td className="w-44 text-muted">{tr(lang, "행동", "Action")}</td><td className="mono">{act ? `${act.type ?? "—"}${act.amount != null ? ` · ${won(act.amount)}` : ""}${act.target ? ` → ${act.target}` : ""}` : c.tool ? `${c.tool.name}(${(c.tool.args ?? []).join(", ")})` : (a.action ? `${a.action.type}` : "—")}</td></tr>
              <tr><td className="w-44 text-muted">{tr(lang, "요청자(위임)", "Requester (on behalf of)")}</td><td>{a.requestedBy}{c.onBehalfOf ? ` · ${typeof c.onBehalfOf === "string" ? c.onBehalfOf : c.onBehalfOf.id}` : ""}</td></tr>
              <tr><td className="w-44 text-muted">{tr(lang, "영향 등급 / 자율 레벨", "Impact grade / autonomy level")}</td><td>{c.autonomy.grade != null ? `A${c.autonomy.grade}` : "—"}{act?.impact ? ` ${act.impact}` : ""}{act?.external ? ` · ${tr(lang, "외부", "external")}` : ""} / {tr(lang, "레벨", "level")} {c.autonomy.level}</td></tr>
              <tr><td className="w-44 text-muted">{tr(lang, "관문 · 정책", "Gate · policy")}</td><td>{a.gate}{c.gate.policy ? ` · ${c.gate.policy}` : ""}{c.gate.stage ? ` · ${c.gate.stage}` : ""}</td></tr>
              <tr><td className="w-44 text-muted">{tr(lang, "근거 판정", "Basis findings")}</td><td>{c.findings.length === 0 ? "—" : c.findings.map((f: any) => <Link key={f.id} className="mr-1" href={`/findings/${f.id}`}><Chip>{f.ruleId} · {f.verdict}</Chip></Link>)}</td></tr>
              <tr><td className="w-44 text-muted">trace</td><td className="mono"><Link className="text-primary" href={`/findings?trace=${a.traceId}`}>{shortHash(a.traceId)}</Link></td></tr>
            </tbody></table>
          </section>
          <section className="card p-4 text-sm" data-testid="spend">
            <h2 className="mb-2 font-semibold">{tr(lang, "지출 상한 · 보상 경로 (AG-D6-07)", "Spend limit · compensation (AG-D6-07)")}</h2>
            {sp ? (<>
              <div className="text-xs">{tr(lang, "일 상한", "Daily limit")} {won(sp.dailyLimit)} · {tr(lang, "오늘 누적", "spent today")} {won(sp.spentToday)} · {tr(lang, "이번", "this")} {won(sp.amount)}</div>
              {sp.dailyLimit ? (
                <div className="my-2 h-3 w-full overflow-hidden rounded bg-line" role="meter" aria-valuenow={Math.round((sp.ratio ?? 0) * 100)} aria-label="spend">
                  <div className="flex h-full"><div style={{ width: pct(sp.spentToday / sp.dailyLimit), background: "var(--sev-info)" }} /><div style={{ width: pct(sp.amount / sp.dailyLimit), background: over ? "var(--verdict-block)" : "var(--verdict-approval)" }} /></div>
                </div>) : <p className="my-1 text-xs text-muted">{tr(lang, "일 상한 미설정 — 정책 agentParams.d6-07.dailyLimit", "No daily limit — set policy agentParams.d6-07.dailyLimit")}</p>}
              <div className="text-xs">{tr(lang, "승인 시", "If approved")} {sp.ratio != null ? `${(sp.ratio * 100).toFixed(0)}%` : "—"} · {tr(lang, "승인 임계", "approval threshold")} {won(sp.approvalThreshold)} {sp.amount > sp.approvalThreshold ? tr(lang, "초과", "exceeded") : ""} · {tr(lang, "건당 상한", "per-action cap")} {won(sp.spendLimit)}</div>
              {over && <p className="mt-1 text-xs font-semibold" style={{ color: "var(--verdict-block)" }}>{tr(lang, "상한 초과 — 승인 불가", "Over the limit — cannot approve")}</p>}
              <div className="mt-2 text-xs">{tr(lang, "보상 경로", "Compensation")}: {sp.compensation ? <span>{typeof sp.compensation === "string" ? sp.compensation : JSON.stringify(sp.compensation)}</span>
                : tr(lang, "취소 API 없음 → 보상: 환수 요청 런북 (사건 대응 O07)", "No cancel API → compensate via the claw-back runbook (incident response O07)")}</div>
            </>) : <p className="text-xs text-muted">{tr(lang, "금전 행동 아님 — 지출 상한 해당 없음", "Not a monetary action — no spend limit")}</p>}
          </section>
        </div>
        <div className="space-y-4">
          <section className="card p-4 text-sm" data-testid="two-person">
            <h2 className="mb-2 font-semibold">{tr(lang, `${a.required}인 승인 진행 — ${yes.length}/${a.required}`, `Approvals — ${yes.length}/${a.required}`)}</h2>
            <ol className="space-y-1 text-xs">
              {a.decisions.map((d: any, i: number) => <li key={d.principal}>{i + 1}. <b>{d.principal}</b> {d.decision === "approve" ? tr(lang, "승인 ✓", "approved ✓") : tr(lang, "거절 ✗", "rejected ✗")} {fmtTime(d.at)} — {tr(lang, "사유", "reason")}: {d.reason}</li>)}
              {a.status === "pending" && <li>{a.decisions.length + 1}. <b>{who}</b> ({tr(lang, "나", "me")}) — {tr(lang, "결정 대기", "pending")}</li>}
            </ol>
            <p className="mt-2 text-xs">{own ? <span style={{ color: "var(--verdict-block)" }}>{tr(lang, "✗ 요청자 본인 — 승인 비활성", "✗ You are the requester — approve disabled")}</span>
              : already ? <span style={{ color: "var(--verdict-block)" }}>{tr(lang, "✗ 이미 결정한 승인자", "✗ You already decided")}</span>
              : tr(lang, "요청자·1차 승인자와 다름 확인 ✓", "Different from requester and first approver ✓")}</p>
          </section>
          <section className="card p-4 text-sm" data-testid="trust">
            <h2 className="mb-2 font-semibold">{tr(lang, "신뢰 악용 검사 (AG-X03)", "Trust-abuse check (AG-X03)")} {c.trust.warn && <Chip>{tr(lang, "경고 — 거절 권장", "warning — reject advised")}</Chip>}</h2>
            <ul className="space-y-1 text-xs">
              <li>{c.trust.urgency ? "⚠" : "✓"} {c.trust.urgency ? tr(lang, "유도·긴급성 문구 감지", "Coaxing / urgency wording detected") : tr(lang, "유도·긴급성 문구 감지 없음", "No coaxing / urgency wording")}</li>
              <li>{c.trust.repeats24h >= 3 ? "⚠" : "✓"} {tr(lang, `같은 요청자 승인 요청 ${c.trust.repeats24h}회/24h`, `Requests by the same requester ${c.trust.repeats24h}/24h`)}</li>
              <li>{c.trust.x03.length ? "⚠" : "✓"} {c.trust.x03.length ? tr(lang, `자격증명·예외 요구 ${c.trust.x03.length}건`, `${c.trust.x03.length} credential / exception requests`) : tr(lang, "자격증명·예외 요구 없음", "No credential / exception requests")}</li>
              {c.trust.x03.map((f: any) => <li key={f.id} className="ml-3 text-muted">“{f.evidence?.[0]?.note ?? f.ruleId}” <Link className="text-primary" href={`/findings/${f.id}`}>{f.ruleId}</Link></li>)}
            </ul>
            <p className="mt-1 text-[11px] text-muted">{tr(lang, "에이전트 설명문은 인용으로만 표시", "Agent text is shown only as a quote")}</p>
          </section>
          {a.status === "pending" && (
            <form action={approve} className="card space-y-2 p-4 text-sm" data-testid="decide">
              <input type="hidden" name="id" value={a.id} /><input type="hidden" name="back" value={`/approvals/${a.id}`} />
              <label className="block text-xs font-semibold">{tr(lang, "결정 사유 (필수 · MSG-003)", "Decision reason (required · MSG-003)")}
                <input name="reason" required className="input mt-1 w-full" disabled={!!block} placeholder={tr(lang, "예: 계약·한도 확인, 수취 계좌 사전 등록 일치", "e.g. contract and limit checked, payee pre-registered")} /></label>
              <div className="flex gap-2" title={block || undefined}>
                <button formAction={reject} className="btn btn-danger" disabled={!!block}>{tr(lang, "거절", "Reject")}</button>
                <button className="btn btn-primary" disabled={!!block || over}>{tr(lang, `승인 (${Math.min(yes.length + 1, a.required)}/${a.required}${yes.length + 1 >= a.required ? " 확정" : ""})`, `Approve (${Math.min(yes.length + 1, a.required)}/${a.required}${yes.length + 1 >= a.required ? ", final" : ""})`)}</button>
              </div>
              {block && <p className="text-xs text-muted">{block}</p>}
              <p className="text-[11px] text-muted">{tr(lang, "결정은 증적 원장에 기록 · 승인 확정 후 행동 재개, 거절 = 행동 취소·요청 에이전트 통지", "Decisions are recorded in the ledger · approval resumes the action; rejection cancels it and notifies the agent")}</p>
            </form>
          )}
        </div>
      </div>
    </>
  );
}
