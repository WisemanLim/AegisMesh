// SCR-G02 도구 호출 판정 상세 — 인자·사전조건 / 드라이런 영향 / 명령 주입 검사 / 근거·원장 + 승인 카드. 인자 원문은 저장돼 있지 않다.
import Link from "next/link";
import { notFound } from "next/navigation";
import { Banner, Chip, SeverityBadge, VerdictBadge } from "@/components/Badges";
import { Inspector } from "@/components/Inspector";
import { PageHeader } from "@/components/Shell";
import { approve, reject } from "@/app/approvals/actions";
import { ApiError, api } from "@/lib/api";
import { fmtTime, shortHash } from "@/lib/format";
import { tr, LX, sumL } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";

const SEC = [["args", "① 인자·사전조건", "① Args · preconditions", ["d3-01", "d3-07", "d3-06", "d3-05", "d4-03"]],
  ["dry", "② 드라이런 영향", "② Dry-run impact", ["d3-01"]], ["inj", "③ 명령 주입·장악 검사", "③ Injection · compromise checks", ["d3-02", "d3-03", "d3-04"]]] as const;

export default async function CallDetail({ params, searchParams }: { params: Promise<{ d: string; cid: string }>; searchParams: Promise<{ msg?: string }> }) {
  const [{ lang }, user, { cid }, { msg }] = await Promise.all([prefs(), me(), params, searchParams]);
  let x: any;
  try {
    x = await api(`/v1/domains/d3/calls/${encodeURIComponent(cid)}`);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound();
    throw e;
  }
  const g = x.gate, sh = x.shape, tool = sh.tool ?? {};
  const top = x.findings.find((f: any) => (f.effective ?? f.verdict) === g.verdict && f.verdict !== "allow") ?? x.findings[0];
  const dry = x.findings.flatMap((f: any) => f.evidence.filter((e: any) => e.kind === "dryrun").map((e: any) => ({ ...e, agent: f.agent })));
  const apr = x.approval;
  return (
    <>
      <PageHeader crumb={`${tr(lang, "위험 영역", "Risk domains")} › D3 › ${tr(lang, "도구 호출", "Tool call")}`} title={`call ${shortHash(cid)} · ${sh.principal ?? "—"}${sh.onBehalfOf ? ` (${sh.onBehalfOf})` : ""} → ${tool.name ?? "—"}`} />
      {msg && <div className="mb-3"><Banner tone={/^(실패|Failed)/.test(msg) ? "danger" : "info"}>{msg}</Banner></div>}
      <div className="mb-3 flex flex-wrap items-center gap-2 text-sm" data-testid="call-head">
        <VerdictBadge v={g.verdict} />{top && <SeverityBadge s={top.severity} />}<span className="mono">trace <Link className="text-primary" href={`/findings?trace=${cid}`}>{shortHash(cid)}</Link></span>
        {top && <span className="mono">{top.ruleId} · conf {top.confidence}</span>}<span>{g.latencyMs}ms</span><span className="text-muted">{g.policy} · {g.stage}</span>
        {x.findings.some((f: any) => !f.valid) && <b style={{ color: "var(--verdict-block)" }}>{tr(lang, "무효 판정 포함(근거 없음)", "includes invalid verdicts (no evidence)")}</b>}
      </div>
      <div className="grid grid-cols-[1fr_360px] gap-4">
        <div className="space-y-4">
          <section className="card space-y-2 p-4 text-sm" data-testid="call-args">
            <h2 className="font-semibold">{tr(lang, SEC[0][1], SEC[0][2])}</h2>
            <p className="text-xs">{tr(lang, "도구", "Tool")} <span className="mono">{tool.name}</span> · {tr(lang, "인자", "args")} {(tool.args ?? []).map((a: string) => <Chip key={a}>{a}</Chip>)} · {tr(lang, "요구 범위", "required scopes")} {(tool.requiredScopes ?? []).join(", ") || "—"} · {tool.approved ? tr(lang, "사전 승인됨", "pre-approved") : tr(lang, "미승인", "not approved")}</p>
            <div className="rounded bg-[#f6f7f9] p-2 text-xs text-muted">{tr(lang, "인자 값: 원문 미보존(MSG-012) — 인자 이름과 판정 근거(위치)만 남는다", "Argument values: not retained (MSG-012) — only argument names and evidence locations remain")}</div>
            <Rows lang={lang} fs={x.findings.filter((f: any) => (SEC[0][3] as readonly string[]).includes(f.agent))} />
          </section>
          <section className="card space-y-2 p-4 text-sm" data-testid="call-dry">
            <h2 className="font-semibold">{tr(lang, SEC[1][1], SEC[1][2])}</h2>
            {dry.length ? dry.map((e: any, i: number) => <p key={i} className="text-xs" style={{ color: "var(--verdict-approval)" }}>⚠ {LX(lang, e.note)} <span className="text-muted">({e.location})</span></p>)
              : <p className="text-xs text-muted">{tr(lang, "드라이런 결과 없음 — 호출자가 트랜잭션 롤백 모드로 실행해 params.dryRun {tables, rows, reversible} 을 보내면 임계(d3-01 maxRowsWithoutApproval)와 비교한다", "No dry-run result — when the caller runs in rollback mode and sends params.dryRun {tables, rows, reversible}, it is compared with the threshold (d3-01 maxRowsWithoutApproval)")}</p>}
          </section>
          <section className="card space-y-2 p-4 text-sm" data-testid="call-inj">
            <h2 className="font-semibold">{tr(lang, SEC[2][1], SEC[2][2])}</h2>
            <Rows lang={lang} fs={x.findings.filter((f: any) => (SEC[2][3] as readonly string[]).includes(f.agent))} />
            <p className="text-xs text-muted">{tr(lang, "셸 미경유 실행·인자 허용목록·위험 패턴(; | $( `) 차단·실행 전 정적 검사", "No-shell execution · argument allowlist · dangerous patterns (; | $( `) blocked · static checks before execution")}</p>
          </section>
          <section className="card space-y-2 p-4 text-sm" data-testid="call-ledger">
            <h2 className="font-semibold">{tr(lang, "④ 근거·원장", "④ Evidence · ledger")}</h2>
            <p className="text-xs">{tr(lang, "판정 기록", "Gate record")} #{x.ledger?.seq} · <span className="mono">{shortHash(x.ledger?.hash, 16)}</span> · {fmtTime(x.ledger?.at)}</p>
            <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "에이전트", "Agent")}</th><th>{tr(lang, "규칙", "Rule")}</th><th>{tr(lang, "원판정", "Raw")}</th><th>{tr(lang, "유효", "Effective")}</th><th>{tr(lang, "정책 사유", "Policy reasons")}</th></tr></thead>
              <tbody>{(g.decisions ?? []).map((d: any, i: number) => <tr key={i}><td>{d.agent}</td><td className="mono">{d.ruleId}</td><td>{d.original}</td><td><VerdictBadge v={d.effective} /></td><td>{(d.reasons ?? []).join("; ") || "—"}</td></tr>)}</tbody></table>
          </section>
        </div>
        <aside className="space-y-4">
          <section className="card space-y-2 p-4 text-sm" data-testid="approval-card">
            <h2 className="font-semibold">{tr(lang, "승인 요청", "Approval request")}</h2>
            {!apr ? <p className="text-xs text-muted">{tr(lang, "승인 대상 아님", "No approval needed")}</p> : (
              <>
                <p className="text-xs"><span className="mono">{apr.id}</span> · <b>{apr.status}</b> · {tr(lang, `승인 ${apr.decisions.filter((d: any) => d.decision === "approve").length}/${apr.required}`, `approvals ${apr.decisions.filter((d: any) => d.decision === "approve").length}/${apr.required}`)}</p>
                <p className="text-xs">{LX(lang, sumL(lang, apr.summary))}</p>
                <p className="text-xs text-muted">{tr(lang, "요청", "Requested by")} {apr.requestedBy} · {fmtTime(apr.createdAt)}</p>
                <ul className="text-xs">{apr.decisions.map((d: any, i: number) => <li key={i}>{d.principal}: {d.decision} — {LX(lang, d.reason)}</li>)}</ul>
                {apr.status === "pending" && can(user, "approve") && (
                  <form className="space-y-2">
                    <input type="hidden" name="id" value={apr.id} /><input type="hidden" name="back" value={`/domains/d3/calls/${cid}`} />
                    <input name="reason" required className="input w-full text-xs" placeholder={tr(lang, "사유 (필수)", "Reason (required)")} aria-label="reason" />
                    <div className="flex gap-2"><button formAction={approve} className="btn btn-primary text-xs">{tr(lang, "승인", "Approve")}</button><button formAction={reject} className="btn btn-secondary text-xs">{tr(lang, "거절", "Reject")}</button></div>
                  </form>)}
                <p className="text-xs text-muted">{tr(lang, "사유 입력 필수 · 본인 요청 승인 불가 · 결정은 원장 기록", "Reason required · you cannot approve your own request · decisions are ledgered")}</p>
              </>)}
          </section>
          <section className="card space-y-2 p-4 text-sm">
            <h2 className="font-semibold">{tr(lang, "재검사 (붙여 넣은 인자, 저장 안 함)", "Re-inspect (pasted args, no save)")}</h2>
            <Inspector agents={["d3-01", "d3-02", "d3-04"].map((id) => ({ id, label: id }))} samples={Object.fromEntries(["d3-01", "d3-02", "d3-04"].map((id) => [id, { tool: { name: tool.name ?? "", args: Object.fromEntries((tool.args ?? []).map((a: string) => [a, ""])) } }]))} />
          </section>
        </aside>
      </div>
    </>
  );
}

function Rows({ lang, fs }: { lang: "ko" | "en"; fs: any[] }) {
  return (
    <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "검사", "Check")}</th><th>{tr(lang, "판정", "Verdict")}</th><th>{tr(lang, "규칙", "Rule")}</th><th>{tr(lang, "근거", "Evidence")}</th></tr></thead>
      <tbody>{fs.length === 0 ? <tr><td colSpan={4} className="text-muted">{tr(lang, "바인딩된 에이전트 없음", "No bound agents")}</td></tr> : fs.map((f: any) => (
        <tr key={f.id}><td>{f.agent}</td><td><VerdictBadge v={f.effective ?? f.verdict} /></td><td className="mono"><Link className="text-primary" href={`/findings/${f.id}`}>{f.ruleId}</Link></td>
          <td>{f.evidence.map((e: any, i: number) => <div key={i}>{LX(lang, e.note)}{e.location && <span className="text-muted"> · {e.location}</span>}</div>)}</td></tr>))}</tbody></table>
  );
}
