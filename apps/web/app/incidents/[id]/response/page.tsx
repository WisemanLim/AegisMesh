// SCR-O07 사고 대응 런북·포렌식 재현 — 탐지→봉쇄→근절→복구→사후 검토 단계, 단계 실행(고위험 승인 경유), 포렌식 보존(법적 보존), L3 재현 결과.
import Link from "next/link";
import { notFound } from "next/navigation";
import { Banner, Chip, SeverityBadge } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { ApiError, api } from "@/lib/api";
import { fmtTime, shortHash } from "@/lib/format";
import { LX, t as tk, tr } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { preserve, replay, runStep } from "../../response-actions";

const iso = (lang: "ko" | "en", x: string) => (x?.startsWith("L0") ? tr(lang, "L0 (L3 런타임 없음 — 프로세스 안 재생)", "L0 (no L3 runtime — replayed in-process)") : x);
const PH: Record<string, [string, string]> = { detect: ["탐지", "Detect"], contain: ["봉쇄", "Contain"], eradicate: ["근절", "Eradicate"], recover: ["복구", "Recover"], review: ["사후 검토", "Review"] };

export default async function IncidentResponse({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<{ msg?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const { id } = await params;
  const { msg } = await searchParams;
  let r: any;
  try {
    r = await api(`/v1/incidents/${encodeURIComponent(id)}/response`);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound();
    throw e;
  }
  const i = r.incident;
  const write = can(user, "incident");
  const pend = Object.fromEntries(r.pending.map((p: any) => [p.step, p]));
  const last = r.replays.at(-1);
  return (
    <>
      <PageHeader crumb={`${tk(lang, "groupOps")} › ${tk(lang, "incidents")} › ${i.id} › ${tr(lang, "대응", "Response")}`} title={tr(lang, `사고 대응 — ${i.title}`, `Incident response — ${LX(lang, i.title)}`)}
        actions={<Link className="btn btn-secondary" href={`/incidents/${i.id}`}>‹ {tr(lang, "사건 상세", "Incident")}</Link>} />
      {msg && <div className="mb-3"><Banner tone={/^(실패|Failed)/.test(msg) ? "danger" : "info"}>{msg}</Banner></div>}
      <div className="card mb-4 flex flex-wrap items-center gap-2 p-3 text-sm" data-testid="phases">
        <SeverityBadge s={i.severity} /><Chip>{i.domain}</Chip><Chip>{i.status}{i.contained ? ` · ${tr(lang, "봉쇄됨", "contained")}` : ""}</Chip>
        <span className="ml-2 flex items-center gap-1">{r.phases.map((p: any, n: number) => (
          <span key={p.id} className="flex items-center gap-1">{n > 0 && <span className="text-muted">→</span>}
            <span aria-current={r.current === p.id ? "step" : undefined} className={`rounded-full px-3 py-0.5 text-xs ${p.complete ? "bg-primary-soft text-primary" : r.current === p.id ? "bg-primary text-white" : "border border-line"}`}>
              {p.complete ? "✓ " : ""}{tr(lang, ...PH[p.id])}</span></span>))}</span>
        <span className="ml-auto text-xs text-muted">{i.agents.join(" · ")}</span>
      </div>
      <div className="grid grid-cols-[1fr_400px] gap-4">
        <section className="card p-4 text-sm" data-testid="runbook-steps">
          <h2 className="mb-2 font-semibold">{tr(lang, "런북 단계 — 실행·승인·결과는 원장에 기록", "Runbook steps — runs, approvals and results are recorded")}</h2>
          {r.phases.map((p: any) => (
            <div key={p.id} className="mb-3">
              <h3 className="mb-1 text-xs font-semibold uppercase text-muted">{tr(lang, ...PH[p.id])}</h3>
              <ol className="space-y-1.5">{p.steps.map((st: any) => {
                const d = st.done, wait = pend[st.id];
                return (
                  <li key={st.id} className="flex items-center gap-2 rounded border border-line px-2 py-1.5" data-step={st.id}>
                    <span className="w-5 text-center">{d ? "✓" : wait ? "⏳" : "·"}</span>
                    <div className="flex-1">
                      <div>{tr(lang, st.ko, st.en)}</div>
                      <div className="text-xs text-muted">{d ? <>{tr(lang, `완료 ${fmtTime(d.at)} · ${d.by}`, `done ${fmtTime(d.at)} · ${d.by}`)}{d.note ? <> · <span data-user>{d.note}</span></> : null}</>
                        : wait ? <>{tr(lang, "승인 대기", "awaiting approval")} <Link className="text-primary" href={`/approvals/${wait.id}`}>{wait.id}</Link></> : tr(lang, "대기", "pending")}</div>
                    </div>
                    {write && !d && !wait && (
                      <form action={runStep} className="flex items-center gap-1">
                        <input type="hidden" name="id" value={i.id} /><input type="hidden" name="step" value={st.id} />
                        {st.action === "note" && <input name="note" required className="input h-7 w-44 text-xs" placeholder={tr(lang, "기록 (필수)", "Note (required)")} aria-label={`note ${st.id}`} />}
                        <button className="btn btn-primary h-7 text-xs">{st.action === "approval" ? tr(lang, "승인 요청", "Request approval") : tr(lang, "실행", "Run")}</button>
                      </form>
                    )}
                  </li>
                );
              })}</ol>
            </div>
          ))}
          {r.phases.find((p: any) => p.id === "eradicate")?.steps.find((s: any) => s.id === "reassess")?.done?.reassessed && (() => {
            const ra = r.phases.find((p: any) => p.id === "eradicate").steps.find((s: any) => s.id === "reassess").done.reassessed;
            return <p className="text-xs" data-testid="reassessed">{tr(lang, `재평가 ${ra.total}건 · 유효 판정 변화 ${ra.changed.length}건`, `Re-assessed ${ra.total} · ${ra.changed.length} effective verdicts changed`)}{ra.changed.slice(0, 5).map((c: any) => ` · ${c.agent} ${c.before}→${c.after}`).join("")}</p>;
          })()}
        </section>
        <div className="space-y-4">
          <section className="card p-4 text-sm" data-testid="forensic">
            <h2 className="mb-2 font-semibold">{tr(lang, "포렌식 보존 (재현 자료)", "Forensic preservation (replay material)")}</h2>
            {r.forensic ? (<>
              <ul className="space-y-0.5 text-xs">
                <li>✓ {tr(lang, "판정", "Findings")} {r.forensic.counts?.findings ?? 0} · {tr(lang, "판정 기록(seq·해시)", "records (seq · hash)")} {r.forensic.counts?.records ?? 0}</li>
                <li>✓ {tr(lang, "정책 스냅샷", "Policy snapshot")} {r.forensic.bundle?.policy?.ref ?? "—"}</li>
                <li>✓ {tr(lang, "에이전트 버전", "Agent versions")} {Object.entries(r.forensic.bundle?.agents ?? {}).map(([a, v]) => `${a}@${v}`).join(" · ") || "—"}</li>
                <li>✓ {tr(lang, "입력 원문 미보존 — 근거 구간만", "Raw input not kept — evidence spans only")}</li>
              </ul>
              <p className="mt-1 text-xs"><Chip tone="primary">{tr(lang, "법적 보존 ON — 만료 배치 제외", "Legal hold ON — excluded from expiry")}</Chip></p>
              <p className="mono mt-1 text-[11px] text-muted">sha256 {shortHash(r.forensic.digest, 16)} · #{r.forensic.seq} · {fmtTime(r.forensic.at)}</p>
            </>) : <p className="text-xs text-muted">{tr(lang, "아직 보존 안 함", "Not preserved yet")}</p>}
            {write && <form action={preserve} className="mt-2"><input type="hidden" name="id" value={i.id} /><button className="btn btn-secondary h-7 text-xs" data-testid="preserve">{r.forensic ? tr(lang, "다시 보존", "Preserve again") : tr(lang, "포렌식 보존", "Preserve")}</button></form>}
          </section>
          <section className="card p-4 text-sm" data-testid="replay">
            <h2 className="mb-2 font-semibold">{tr(lang, "L3 재현 — 1회용 격리에서 보존본 재생", "L3 replay — replay the preserved set in a one-off sandbox")}</h2>
            {write && <form action={replay}><input type="hidden" name="id" value={i.id} /><button className="btn btn-primary h-7 text-xs" disabled={!r.forensic} title={r.forensic ? undefined : tr(lang, "포렌식 보존 먼저", "Preserve first")} data-testid="replay-run">{tr(lang, "재현 실행", "Run replay")}</button></form>}
            {last ? (<>
              <p className="mt-2 text-xs"><b>{last.matched}/{last.total} {tr(lang, "일치", "matched")}</b> · {iso(lang, last.isolation)} · {fmtTime(last.at)}</p>
              <table className="grid-table mt-1 text-xs"><thead><tr><th>{tr(lang, "판정", "Finding")}</th><th>{tr(lang, "원 사건", "Original")}</th><th>{tr(lang, "재현", "Replay")}</th><th>{tr(lang, "일치", "Match")}</th></tr></thead>
                <tbody>{(last.rows ?? []).slice(0, 12).map((x: any) => (
                  <tr key={x.finding}><td className="mono">{x.agent}<span className="text-muted"> · {x.mode}</span></td><td>{x.expected}</td><td>{x.replayed}</td>
                    <td>{x.match ? "✓" : <b style={{ color: "var(--verdict-block)" }}>✗ {x.versionChanged ? tr(lang, `버전 ${x.versionThen}→${x.versionNow}`, `version ${x.versionThen}→${x.versionNow}`) : tr(lang, "정책 차이", "policy diff")}</b>}</td></tr>))}</tbody></table>
            </>) : <p className="mt-2 text-xs text-muted">{tr(lang, "재현 기록 없음", "No replay yet")}</p>}
          </section>
          <section className="card p-4 text-sm" data-testid="external">
            <h2 className="mb-1 font-semibold">{tr(lang, "외부 대응 도구 연동", "External response tools")}</h2>
            <p className="text-xs text-muted">{tr(lang, "사례 관리·IoC 공유·호스트 경보 도구(TheHive·MISP·Wazuh 등)는 알림 채널·SIEM 내보내기로 연동 — 결과 요약만 표시, 외부 화면 모사 안 함", "Case management, IoC sharing and host alerting (TheHive, MISP, Wazuh …) connect via notification channels and SIEM export — summaries only, external screens are not mimicked")}</p>
            <Link className="text-xs text-primary" href="/notifications">{tr(lang, "알림 채널 ›", "Notification channels ›")}</Link>
          </section>
        </div>
      </div>
    </>
  );
}
