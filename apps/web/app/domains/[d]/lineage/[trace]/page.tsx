// SCR-J03 실행 계보·루프 감지 — 하위 에이전트 생성 트리(깊이·팬아웃·생성 예산), 상태 해시 반복·진전 없음·타임아웃, 상한 설정, 강제 종료.
import Link from "next/link";
import { notFound } from "next/navigation";
import { Banner, SeverityBadge, VerdictBadge } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { forceStop } from "@/app/domains/actions";
import { ApiError, api } from "@/lib/api";
import { fmtTime, shortHash } from "@/lib/format";
import { tr, LX } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { SettingsCard } from "../../../_screens/common";

export default async function LineageRun({ params, searchParams }: { params: Promise<{ d: string; trace: string }>; searchParams: Promise<{ msg?: string }> }) {
  const [{ lang }, user, { trace }, { msg }] = await Promise.all([prefs(), me(), params, searchParams]);
  let x: any;
  try {
    x = await api(`/v1/domains/d6/runs/${encodeURIComponent(trace)}`);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound();
    throw e;
  }
  const sh = x.shape, g = x.gate;
  const lim2 = x.limits["d6-02"], lim3 = x.limits["d6-03"];
  const depthMax = Math.max(0, ...x.nodes.map((n: any) => n.depth ?? 0));
  const byDepth = Array.from({ length: depthMax + 1 }, (_, i) => x.nodes.filter((n: any) => (n.depth ?? 0) === i));
  const loopF = x.findings.filter((f: any) => ["d6-02", "d6-03"].includes(f.agent));
  const deg = x.findings.filter((f: any) => f.evidence.some((e: any) => e.kind === "degraded"));
  return (
    <>
      <PageHeader crumb={`${tr(lang, "위험 영역", "Risk domains")} › D6 › ${tr(lang, "실행 계보", "Execution lineage")} › ${shortHash(trace)}`} title={tr(lang, `실행 계보 — ${sh.principal ?? "—"}`, `Execution lineage — ${sh.principal ?? "—"}`)} />
      {msg && <div className="mb-3"><Banner tone={/^(실패|Failed)/.test(msg) ? "danger" : "info"}>{msg}</Banner></div>}
      {deg.length > 0 && <div className="mb-3"><Banner tone="danger">{tr(lang, `에이전트 무응답 → fail-closed 강등 (${deg.map((f: any) => f.agent).join(", ")})`, `Agent unresponsive → fail-closed degradation (${deg.map((f: any) => f.agent).join(", ")})`)}</Banner></div>}
      <div className="mb-3 flex flex-wrap items-center gap-2 text-sm" data-testid="run-head">
        <VerdictBadge v={g.verdict} />{loopF[0] && <SeverityBadge s={loopF[0].severity} />}<span>{sh.principal ?? "—"}</span>
        <span className="mono">trace <Link className="text-primary" href={`/findings?trace=${trace}`}>{shortHash(trace)}</Link></span><span className="text-muted">{fmtTime(x.ledger?.at)}</span>
      </div>
      <div className="grid grid-cols-2 gap-4">
        <section className="card space-y-2 p-4 text-sm" data-testid="tree">
          <h2 className="font-semibold">{tr(lang, "① 계보 트리 (깊이별)", "① Lineage tree (by depth)")}</h2>
          {x.nodes.length === 0 ? <p className="text-xs text-muted">{tr(lang, "history 없음 — 호출자가 history {agent, parent, depth, tool, stateHash} 를 보내면 그린다", "No history — drawn when the caller sends history {agent, parent, depth, tool, stateHash}")}</p>
            : byDepth.map((row, i) => (
              <div key={i} className="flex flex-wrap items-center gap-2 text-xs"><span className="w-14 text-muted">{tr(lang, `깊이 ${i}`, `depth ${i}`)}</span>
                {row.map((n: any, j: number) => <span key={j} className="rounded border px-2 py-0.5" style={{ borderColor: i >= (lim2.maxDepth ?? 5) ? "var(--verdict-block)" : undefined }}>{n.agent ?? "—"}{n.tool && <span className="text-muted"> · {n.tool}</span>}</span>)}
              </div>))}
          <h3 className="pt-2 font-semibold">{tr(lang, "재귀 판정", "Recursion")}</h3>
          <p className="text-xs">{tr(lang, `호출 깊이 ${depthMax} / 상한 ${lim2.maxDepth ?? 5} · 팬아웃 상한 ${lim2.maxFanout ?? 10} · 생성 예산 ${lim2.spawnBudget ?? "—"}`, `call depth ${depthMax} / max ${lim2.maxDepth ?? 5} · fan-out max ${lim2.maxFanout ?? 10} · spawn budget ${lim2.spawnBudget ?? "—"}`)}</p>
        </section>
        <section className="card space-y-2 p-4 text-sm" data-testid="loop">
          <h2 className="font-semibold">{tr(lang, "② 상태 해시 시퀀스 · 루프 판정", "② State-hash sequence · loop verdict")}</h2>
          <div className="flex flex-wrap gap-1 text-xs">{x.states.map((st: any, i: number) => <span key={i} className="mono rounded px-1" style={{ background: st.repeat ? "#fdecec" : "#f6f7f9", color: st.repeat ? "var(--verdict-block)" : undefined }}>{st.hash}</span>)}</div>
          <ul className="text-xs">{loopF.map((f: any) => <li key={f.id}><VerdictBadge v={f.effective ?? f.verdict} /> {f.agent} <Link className="text-primary mono" href={`/findings/${f.id}`}>{f.ruleId}</Link> — {f.evidence.map((e: any) => LX(lang, e.note)).join("; ")}</li>)}</ul>
          <p className="text-xs">{tr(lang, `반복 임계 ${lim3.maxRepeat ?? 3} · 진전 없음 ${lim3.maxNoProgress ?? 4}스텝 · 타임아웃 ${lim3.maxRunSec ?? 900}초`, `repeat limit ${lim3.maxRepeat ?? 3} · no progress ${lim3.maxNoProgress ?? 4} steps · timeout ${lim3.maxRunSec ?? 900} s`)}</p>
          <h3 className="pt-2 font-semibold">{tr(lang, "조치", "Actions")}</h3>
          <p className="text-xs text-muted">{tr(lang, "내구 실행(체크포인트) 재개는 실행 엔진(Temporal 등) 몫 — 이 설치에는 연동 없음. 상한을 조정한 뒤 호출자가 재개한다.", "Resuming from a durable-execution checkpoint belongs to the workflow engine (e.g. Temporal) — not integrated here. Adjust limits, then the caller resumes.")}</p>
          {sh.principal && can(user, "incident") && (
            <form action={forceStop} className="flex gap-2"><input type="hidden" name="trace" value={trace} /><input type="hidden" name="name" value={sh.principal} />
              <input name="reason" required className="input h-8 flex-1 text-xs" placeholder={tr(lang, "강제 종료 사유 (격리·토큰·신원 폐기)", "Force-stop reason (quarantine · revoke tokens · identity)")} aria-label="reason" />
              <button className="btn btn-danger h-8 text-xs">{tr(lang, "강제 종료", "Force stop")}</button></form>)}
        </section>
      </div>
      <div className="mt-4 grid grid-cols-2 gap-4">
        <SettingsCard lang={lang} user={user} id="d6-02" principal={sh.principal ?? undefined} title={tr(lang, `③ 상한 — 깊이·팬아웃·생성 예산 (${sh.principal ?? "공통"})`, `③ Limits — depth · fan-out · spawn budget (${sh.principal ?? "shared"})`)} />
        <SettingsCard lang={lang} user={user} id="d6-03" principal={sh.principal ?? undefined} title={tr(lang, `반복 임계·진전 없음·타임아웃 (${sh.principal ?? "공통"})`, `Repeat · no-progress · timeout (${sh.principal ?? "shared"})`)} />
      </div>
    </>
  );
}
