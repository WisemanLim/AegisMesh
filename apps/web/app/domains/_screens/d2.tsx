// D2 데이터 유출 상세 화면 — SCR-F02 민감정보·로그 마스킹, SCR-F03 세션 격리·자격증명·무단 접근, SCR-F04 삭제 전파·학습 데이터 재현 시험.
import Link from "next/link";
import { Banner, Chip, Kpi, VerdictBadge } from "@/components/Badges";
import { Inspector } from "@/components/Inspector";
import { RecallForm } from "@/components/RecallForm";
import { api, safe } from "@/lib/api";
import { fmtTime, shortHash } from "@/lib/format";
import { LX, tr } from "@/lib/i18n";
import { can } from "@/lib/session";
import { erasureCertify, erasureCreate, erasureStore, erasureVerify, runRegression } from "../actions";
import { AgentStrip, DetailHeader, Recent, type ScreenProps, SettingsCard } from "./common";

const ZONES: [string, string, string][] = [["operator", "내부 운영자", "Internal operator"], ["agent_screen", "상담원 화면", "Agent screen"], ["external", "외부 고객 응답", "External reply"], ["external_model", "외부 모델·국외 이전", "External model · cross-border"]];
const TYPES = ["rrn", "card", "passport", "phone", "email"];
const STORE: Record<string, [string, string]> = { primary: ["원본", "Primary"], index: ["벡터 인덱스", "Vector index"], cache: ["캐시", "Cache"], memory: ["장기 메모리", "Long-term memory"], backup: ["백업", "Backup"] };
const ST_COLOR: Record<string, string> = { deleted: "var(--verdict-allow)", scheduled: "#3b6fd8", failed: "var(--verdict-block)", pending: "var(--sev-info)" };

export async function Pii({ lang, user, d, screen, sp }: ScreenProps) {
  const [cfg, obs] = await Promise.all([safe(api("/v1/agents/d2-01/config"), null as any), safe(api("/v1/observability"), null as any)]);
  const zp = (cfg.data?.values?.zonePolicy ?? {}) as Record<string, Record<string, string>>;
  const logs = obs.data?.pipeline?.logs;
  return (
    <>
      <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />
      <AgentStrip lang={lang} ids={["d2-01", "d2-06"]} />
      <div className="grid grid-cols-2 gap-4">
        <SettingsCard lang={lang} user={user} id="d2-01" showRules title={tr(lang, "① 개체 유형 · 탐지기 · 임계 · 조치 (AG-D2-01) + ② 신뢰 구역 정책", "① Entity types · detector · threshold · action (AG-D2-01) + ② trust-zone policy")} />
        <div className="space-y-4">
          <section className="card overflow-hidden text-sm" data-testid="zone-matrix">
            <h2 className="p-3 font-semibold">{tr(lang, "② 신뢰 구역별 노출 정책 (현재)", "② Exposure by trust zone (current)")}</h2>
            <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "구역", "Zone")}</th>{TYPES.map((t) => <th key={t}>{t}</th>)}</tr></thead>
              <tbody>{ZONES.map(([z, ko, en]) => (
                <tr key={z}><td>{tr(lang, ko, en)} <span className="mono text-muted">{z}</span></td>
                  {TYPES.map((t) => { const m = zp[z]?.[t] ?? zp[z]?.["*"] ?? (z === "external_model" ? "block" : "mask");
                    return <td key={t} style={{ color: m === "block" ? "var(--verdict-block)" : m === "raw" ? "#9d6105" : undefined }}>{m}{!zp[z] && <span className="text-muted">*</span>}</td>; })}</tr>
              ))}</tbody></table>
            <p className="p-3 text-xs text-muted">{tr(lang, "* 기본값. 요청 params.zone 으로 구역을 지정한다. 외부 모델·국외 이전은 기본 금지 — 정책에 명시한 유형만 허용, 허용 사실은 정책 버전(원장)에 남는다(MSG-013). 편집: 왼쪽 zonePolicy.",
              "* default. Callers set params.zone. External model / cross-border is denied by default — only types listed in the policy pass, and that permission is recorded as a policy version (ledger, MSG-013). Edit zonePolicy on the left.")}</p>
          </section>
          <section className="card p-4 text-sm">
            <h2 className="mb-2 font-semibold">{tr(lang, "③ 시험 입력 → 판정 · 근거 · 마스킹 결과", "③ Test input → verdict · evidence · masked result")}</h2>
            <Inspector agents={[{ id: "d2-01", label: "d2-01" }]} samples={{ "d2-01": { output: "주민번호 900101-1234568, 계좌 카드 4111-1111-1111-1111 로 환불해 주세요. 연락처 010-1234-5678", params: { zone: "agent_screen" } } }} />
          </section>
        </div>
      </div>
      <div className="mt-4 grid grid-cols-2 gap-4">
        <section className="card space-y-2 p-4 text-sm" data-testid="log-pipeline">
          <h2 className="font-semibold">{tr(lang, "④ 로그 수집 파이프라인 (AG-D2-06)", "④ Log collection pipeline (AG-D2-06)")}</h2>
          {logs ? <p className="flex flex-wrap items-center gap-1 text-xs">{[...logs.receivers, ...logs.processors, ...logs.exporters].map((x: string, i: number) => (
            <span key={x + i} className="flex items-center gap-1"><Chip tone={x === "transform/mask" ? "primary" : undefined}>{x}</Chip>{i < logs.receivers.length + logs.processors.length + logs.exporters.length - 1 && "→"}</span>))}</p>
            : <p className="text-xs text-muted">{tr(lang, "관측 구성 없음", "No observability config")}</p>}
          <dl className="grid grid-cols-[180px_1fr] gap-y-1 text-xs">
            <dt className="text-muted">{tr(lang, "마스킹 규칙", "Masking rules")}</dt><dd>{obs.data?.masking?.length ?? 0} · {obs.data?.collector?.statements ?? 0} statements ({obs.data?.collector?.maskProcessor})</dd>
            <dt className="text-muted">{tr(lang, "원문 적재", "Raw payload stored")}</dt><dd style={{ color: "var(--verdict-allow)" }}>{obs.data?.payload?.stored === false ? tr(lang, "0건 ✓ — 판정 원문·무해화 결과는 저장·전송하지 않는다(설계)", "0 ✓ — verdict raw text and sanitized output are never stored or exported (by design)") : "—"}</dd>
            <dt className="text-muted">{tr(lang, "접근권", "Access")}</dt><dd>{tr(lang, "로그 열람 = 판정·규칙·위치만. 원문 열람 대상 자체가 없다(미보존)", "Log access = verdicts, rules, locations only. There is no raw text to open (not retained)")}</dd>
          </dl>
          <p className="text-xs"><Link className="text-primary" href="/observability">{tr(lang, "관측 · 마스킹 미리보기 ›", "Observability · masking preview ›")}</Link> · <Link className="text-primary" href="/admin/data-protection">{tr(lang, "보존기한(R06) ›", "Retention (R06) ›")}</Link></p>
        </section>
        <SettingsCard lang={lang} user={user} id="d2-06" title={tr(lang, "D2-06 설정 — 로그 최대 보존", "D2-06 settings — max log retention")} />
      </div>
      <div className="mt-4"><Recent lang={lang} ids={["d2-01", "d2-06"]} /></div>
    </>
  );
}

export async function Isolation({ lang, user, d, screen, sp }: ScreenProps) {
  const { data: x } = await safe(api("/v1/domains/d2/isolation"), null as any);
  if (!x) return <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />;
  const reg = x.regression;
  const c = x.counts24h ?? {};
  return (
    <>
      <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />
      <AgentStrip lang={lang} ids={["d2-02", "d2-03", "d2-04"]} />
      <div className="grid grid-cols-2 gap-4">
        <section className="card space-y-2 p-4 text-sm" data-testid="isolation-checks">
          <h2 className="font-semibold">{tr(lang, "① 세션 간 유출 (AG-D2-02) — 캐시 키·네임스페이스", "① Cross-session leaks (AG-D2-02) — cache keys · namespaces")}</h2>
          <ul className="space-y-1 text-xs">
            <li>{x.platformIsolation?.ok ? "✓" : "✗"} {tr(lang, "판정·증적·정책 테넌트 분리(앱 계층 + PostgreSQL RLS)", "Verdict/evidence/policy tenant separation (app layer + PostgreSQL RLS)")} — {x.platformIsolation ? `${x.platformIsolation.passed}/${x.platformIsolation.total} (${fmtTime(x.platformIsolation.at)})` : tr(lang, "플랫폼 시험 기록 없음", "no platform test yet")}</li>
            <li>{x.sessionScopedMemory ? "✓" : "✗"} {tr(lang, "메모리 세션 범위 강제 (d2-02 sessionScopedMemory)", "Session-scoped memory enforced (d2-02 sessionScopedMemory)")}</li>
            <li>{tr(lang, `24h 판정: 테넌트 혼입 ${c["D2-02.cross-tenant"] ?? 0} · 주체 혼입 ${c["D2-02.cross-user"] ?? 0} · 세션 혼입 ${c["D2-02.cross-session"] ?? 0}`, `24h: cross-tenant ${c["D2-02.cross-tenant"] ?? 0} · cross-user ${c["D2-02.cross-user"] ?? 0} · cross-session ${c["D2-02.cross-session"] ?? 0}`)}</li>
          </ul>
          <h3 className="pt-2 font-semibold">{tr(lang, "② 교차 조회 회귀", "② Cross-scope regression")}</h3>
          <table className="grid-table text-xs" data-testid="regression"><thead><tr><th>{tr(lang, "시험", "Case")}</th><th>{tr(lang, "누출/시도", "Leaked/probes")}</th><th></th></tr></thead>
            <tbody>{!reg ? <tr><td colSpan={3} className="text-muted">{tr(lang, "아직 실행 안 함", "Not run yet")}</td></tr> : reg.cases.map((r: any) => (
              <tr key={r.case}><td>{tr(lang, r.title, r.case === "tenant" ? "Tenant → other tenant's docs" : r.case === "user" ? "Principal A → B's docs" : "Session X → Y memory")}</td><td>{r.leaked}/{r.probes}</td><td>{r.ok ? "✓" : <b style={{ color: "var(--verdict-block)" }}>✗</b>}</td></tr>))}</tbody></table>
          {reg && <p className="text-xs text-muted">{fmtTime(reg.at)} · {reg.by} · {tr(lang, `원장 #${reg.seq}`, `ledger #${reg.seq}`)}</p>}
          {can(user, "scan") && <form action={runRegression} className="flex items-center gap-2 text-xs">
            <select name="n" className="input h-7 text-xs" defaultValue="100" aria-label="probes">{[100, 300, 500].map((n) => <option key={n} value={n}>{n}</option>)}</select>
            <button className="btn btn-primary h-7 text-xs">{tr(lang, "회귀 시험 실행", "Run regression")}</button></form>}
        </section>
        <section className="card space-y-2 p-4 text-sm" data-testid="secret-scan">
          <h2 className="font-semibold">{tr(lang, "③ 자격증명 유출 (AG-D2-03) — 지점별 24h", "③ Credential leaks (AG-D2-03) — 24h by location")}</h2>
          <div className="grid grid-cols-3 gap-2">
            {(["prompt", "output", "log"] as const).map((k) => <Kpi key={k} label={tr(lang, { prompt: "프롬프트·컨텍스트", output: "출력", log: "로그(D2-06)" }[k], { prompt: "Prompt · context", output: "Output", log: "Logs (D2-06)" }[k])} value={x.secrets.byLocation[k]} accent={x.secrets.byLocation[k] ? "var(--verdict-block)" : "var(--verdict-allow)"} />)}
          </div>
          <p className="text-xs">{tr(lang, `비밀 브로커 임대: 활성 ${x.secrets.leases.active} · 폐기 ${x.secrets.leases.revoked} · 만료 ${x.secrets.leases.expired}`, `Secrets-broker leases: active ${x.secrets.leases.active} · revoked ${x.secrets.leases.revoked} · expired ${x.secrets.leases.expired}`)} · <Link className="text-primary" href="/admin/identity">{tr(lang, "즉시 폐기·재발급 ›", "Revoke · reissue ›")}</Link></p>
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "시각", "Time")}</th><th>{tr(lang, "유형", "Type")}</th><th>{tr(lang, "위치", "Location")}</th><th>{tr(lang, "판정", "Verdict")}</th></tr></thead>
            <tbody>{x.secrets.recent.length === 0 ? <tr><td colSpan={4} className="text-muted">{tr(lang, "없음", "None")}</td></tr> : x.secrets.recent.map((f: any) => (
              <tr key={f.id}><td>{fmtTime(f.at)}</td><td className="mono"><Link className="text-primary" href={`/findings/${f.id}`}>{f.ruleId}</Link></td><td>{f.evidence.map((e: any) => e.location).join(", ")}</td><td><VerdictBadge v={f.effective ?? f.verdict} /></td></tr>))}</tbody></table>
          <p className="text-xs text-muted">{tr(lang, "유출 키는 형태·위치만 기록(값 없음). 동적 임대 비밀은 즉시 폐기(비밀 브로커) — 정적 키는 임대로 전환 권고", "Leaked keys are recorded by type and location only (no value). Dynamically leased secrets are revoked at once (secrets broker) — move static keys to leases")}</p>
        </section>
      </div>
      <section className="card mt-4 overflow-hidden text-sm" data-testid="access-decisions">
        <h2 className="p-3 font-semibold">{tr(lang, "④ 무단 접근 — 검색 결과 후단 재검증 (AG-D2-04) · 접근 결정 기록", "④ Unauthorized access — post-retrieval re-check (AG-D2-04) · access decisions")}</h2>
        <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "시각", "Time")}</th><th>{tr(lang, "주체(대리)", "Principal (agent)")}</th><th>{tr(lang, "문서", "Document")}</th><th>ACL</th><th>{tr(lang, "프리필터", "Pre-filter")}</th><th>{tr(lang, "후단", "Post-check")}</th><th>{tr(lang, "판정", "Verdict")}</th></tr></thead>
          <tbody>{x.access.length === 0 ? <tr><td colSpan={7} className="text-muted">{tr(lang, "검색 문서가 포함된 판정 없음", "No verdicts with retrieved documents")}</td></tr> : x.access.slice(0, 40).map((r: any, i: number) => (
            <tr key={i}><td>{fmtTime(r.at)}</td><td>{r.principal ?? "—"}{r.agent && ` (${r.agent})`}</td><td className="mono">{r.doc}</td><td>{(r.acl ?? ["*"]).join(", ")}</td><td className="text-muted">—</td>
              <td style={{ color: r.postCheck === "deny" ? "var(--verdict-block)" : "var(--verdict-allow)" }}>{r.postCheck}</td>
              <td><Link href={`/findings/${r.finding}`}><VerdictBadge v={r.verdict} /></Link></td></tr>))}</tbody></table>
        <p className="p-3 text-xs text-muted">{tr(lang, "검색 전 관계 기반 인가(OpenFGA·SpiceDB) 연동은 없다 — 결과 후단 재검증(주체·대리 에이전트 모두 필요)으로 판정. 모든 결정은 원장에 남고 수정·삭제할 수 없다(MSG-016).",
          "No pre-retrieval relationship-based authorization (OpenFGA · SpiceDB) — decided by post-retrieval re-check (both principal and delegate must be allowed). Every decision is in the ledger and cannot be edited or deleted (MSG-016).")}</p>
      </section>
      <div className="mt-4 grid grid-cols-2 gap-4">
        <SettingsCard lang={lang} user={user} id="d2-02" title={tr(lang, "D2-02 설정", "D2-02 settings")} />
        <section className="card p-4 text-sm">
          <h2 className="mb-2 font-semibold">{tr(lang, "시험 입력 (저장 안 함)", "Test input (no save)")}</h2>
          <Inspector agents={[{ id: "d2-04", label: "d2-04" }, { id: "d2-02", label: "d2-02" }]} samples={{
            "d2-04": { text: "급여표 요약", subject: { principal: { id: "kang", roles: ["dev"] }, onBehalfOf: { id: "dev-copilot" } }, retrieval: [{ id: "hr/salary-2026.xlsx", acl: ["role:hr"] }, { id: "kb/fee-policy.pdf" }] },
            "d2-02": { subject: { principal: { id: "agent-a" } }, session: { id: "sx" }, memory: [{ id: "m1", owner: "agent-a", session: "sy", text: "이전 상담 메모" }] } }} />
        </section>
      </div>
    </>
  );
}

export async function Erasure({ lang, user, d, screen, sp }: ScreenProps) {
  const [er, rc] = await Promise.all([safe(api("/v1/erasure"), null as any), safe(api("/v1/recall-tests"), null as any)]);
  const items: any[] = er.data?.items ?? [];
  const sel = items.find((x) => x.id === sp.id) ?? items[0];
  return (
    <>
      <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />
      <AgentStrip lang={lang} ids={["d2-07", "d2-05"]} />
      {!er.data && <Banner tone="warn">{tr(lang, "삭제 요청·재현 시험 결과는 보안 엔지니어·규제 대응·테넌트 관리자만 (privacy 권한)", "Erasure requests and recall results require security engineer / compliance / tenant admin (privacy permission)")}</Banner>}
      {er.data && (
        <div className="grid grid-cols-2 gap-4">
          <section className="card space-y-3 p-4 text-sm" data-testid="erasure">
            <h2 className="font-semibold">{tr(lang, "삭제 요청 · 전파 현황 (AG-D2-07)", "Erasure request · propagation (AG-D2-07)")}</h2>
            <div className="flex flex-wrap gap-1 text-xs">{items.map((x) => (
              <Link key={x.id} href={`/domains/d2/erasure?id=${x.id}`} className={`rounded-full border px-2 py-0.5 ${x.id === sel?.id ? "border-primary text-primary" : "border-line"}`}>{x.id} · {x.state}</Link>))}</div>
            {sel ? (
              <>
                <dl className="grid grid-cols-[120px_1fr] gap-y-1 text-xs">
                  <dt className="text-muted">{tr(lang, "정보주체(해시)", "Subject (hash)")}</dt><dd className="mono">{sel.subjectHash}</dd>
                  <dt className="text-muted">{tr(lang, "근거", "Basis")}</dt><dd>{sel.basis}</dd>
                  <dt className="text-muted">{tr(lang, "접수", "Requested")}</dt><dd>{sel.requestedBy} · {fmtTime(sel.requestedAt)}</dd>
                  <dt className="text-muted">{tr(lang, "처리 기한", "Deadline")}</dt><dd style={{ color: sel.daysLeft < 3 && !sel.certified ? "var(--verdict-block)" : undefined }}>{fmtTime(sel.deadline)} · {tr(lang, `남은 ${sel.daysLeft}일`, `${sel.daysLeft} days left`)}</dd>
                </dl>
                <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "저장소", "Store")}</th><th>{tr(lang, "상태", "Status")}</th><th>{tr(lang, "보고", "Reported")}</th><th></th></tr></thead>
                  <tbody>{Object.entries(sel.stores).map(([k, v]: [string, any]) => (
                    <tr key={k}><td>{tr(lang, ...STORE[k])}</td><td style={{ color: ST_COLOR[v.status] }}>{v.status}</td><td>{v.by ? `${v.by} · ${fmtTime(v.at)}` : "—"}{v.note && ` · ${LX(lang, v.note)}`}</td>
                      <td>{!sel.certified && <form action={erasureStore} className="flex gap-1"><input type="hidden" name="id" value={sel.id} /><input type="hidden" name="store" value={k} />
                        <select name="status" className="input h-6 text-xs" defaultValue={v.status === "pending" ? "deleted" : v.status} aria-label={`status ${k}`}>{["deleted", "failed", "scheduled"].map((x) => <option key={x}>{x}</option>)}</select>
                        <button className="btn btn-secondary h-6 text-xs">{tr(lang, "기록", "Record")}</button></form>}</td></tr>))}</tbody></table>
                {sel.verify && <p className="text-xs">{tr(lang, "잔존 재검사", "Residual check")}: <VerdictBadge v={sel.verify.verdict} /> · {fmtTime(sel.verify.at)} · trace <Link className="text-primary mono" href={`/findings?trace=${sel.verify.traceId}`}>{shortHash(sel.verify.traceId)}</Link>{sel.verify.residual.length > 0 && ` · ${tr(lang, "잔존", "residual")} ${sel.verify.residual.join(", ")}`}</p>}
                {sel.certified ? <p className="text-xs" style={{ color: "var(--verdict-allow)" }} data-testid="erasure-cert">✓ {tr(lang, `삭제 증적 발행 — 원장 #${sel.certified.seq} · ${shortHash(sel.certified.hash, 12)} (해시 체인, 수정·삭제 불가)`, `Erasure receipt — ledger #${sel.certified.seq} · ${shortHash(sel.certified.hash, 12)} (hash chain, immutable)`)}</p> : (
                  <div className="flex gap-2">
                    <form action={erasureVerify}><input type="hidden" name="id" value={sel.id} /><button className="btn btn-secondary text-xs">{tr(lang, "잔존 재검사", "Re-check residuals")}</button></form>
                    <form action={erasureCertify}><input type="hidden" name="id" value={sel.id} /><button className="btn btn-primary text-xs">{tr(lang, "삭제 증적 발행", "Issue receipt")}</button></form>
                  </div>)}
                <p className="text-xs text-muted">{tr(lang, "백업은 보존 만료 시 삭제(scheduled) — 유예 기간(d2-07 backupGraceSec) 안이면 잔존으로 막지 않는다. 실패 저장소만 다시 기록·재검사(MSG-028).", "Backups are deleted at retention expiry (scheduled) — within the grace period (d2-07 backupGraceSec) they do not block. Re-record and re-check failed stores only (MSG-028).")}</p>
              </>
            ) : <p className="text-xs text-muted">{tr(lang, "삭제 요청 없음", "No erasure requests")}</p>}
            <form action={erasureCreate} className="space-y-1 border-t border-line pt-2 text-xs">
              <b>{tr(lang, "삭제 요청 등록", "Register erasure request")}</b>
              <div className="grid grid-cols-[1fr_1fr_80px] gap-2">
                <input name="subject" required className="input" placeholder={tr(lang, "정보주체 식별자 (해시만 저장)", "Data-subject identifier (hash only)")} aria-label="subject" autoComplete="off" />
                <input name="basis" required className="input" placeholder={tr(lang, "근거 (예 개인정보보호법 제36조)", "Basis (e.g. PIPA Art. 36)")} aria-label="basis" />
                <input name="days" type="number" min={1} max={90} defaultValue={10} className="input" aria-label="days" />
              </div>
              <button className="btn btn-primary h-7 text-xs">{tr(lang, "등록", "Register")}</button>
            </form>
          </section>
          <section className="card space-y-3 p-4 text-sm" data-testid="recall">
            <h2 className="font-semibold">{tr(lang, "학습 데이터 재현 시험 (AG-D2-05) · 배포 게이트", "Training-data recall test (AG-D2-05) · release gate")}</h2>
            <RecallForm />
            <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "모델", "Model")}</th><th>{tr(lang, "추출(정확 재현)", "Extraction")}</th><th>MIA AUC</th><th>ε</th><th>{tr(lang, "중복 제거", "Dedup")}</th><th>{tr(lang, "게이트", "Gate")}</th></tr></thead>
              <tbody>{!(rc.data?.items ?? []).length ? <tr><td colSpan={6} className="text-muted">{tr(lang, "시험 이력 없음", "No test runs")}</td></tr> : rc.data.items.map((h: any) => (
                <tr key={h.seq}><td>{h.model} {h.version}</td><td>{(h.extractionRate * 100).toFixed(2)}% / {(h.limits.extraction * 100).toFixed(1)}%</td><td>{h.miaAuc ?? "—"}</td><td>{h.dpEpsilon ?? "—"}</td><td>{h.dedupRate != null ? `${(h.dedupRate * 100).toFixed(1)}%` : "—"}</td>
                  <td style={{ color: h.gate === "pass" ? "var(--verdict-allow)" : "var(--verdict-block)" }}>{h.gate === "pass" ? tr(lang, "통과", "pass") : tr(lang, "차단", "blocked")}</td></tr>))}</tbody></table>
            <p className="text-xs text-muted">{tr(lang, "플랫폼은 출력 표본으로 카나리·보호 코퍼스 재현(추출률)을 직접 잰다. 멤버십 추론·차등 프라이버시는 외부 시험 결과를 받아 기준과 함께 판정. 결과는 취약점 정보 — privacy 권한만 열람.",
              "The platform measures canary / protected-corpus reproduction (extraction rate) from output samples itself. Membership inference and DP come from external harness results and are judged against limits. Results are vulnerability data — privacy permission only.")}</p>
          </section>
        </div>
      )}
      <div className="mt-4 grid grid-cols-2 gap-4">
        <SettingsCard lang={lang} user={user} id="d2-07" title={tr(lang, "D2-07 설정 — 메모리 기본 TTL · 백업 유예", "D2-07 settings — default memory TTL · backup grace")} />
        <SettingsCard lang={lang} user={user} id="d2-05" title={tr(lang, "D2-05 설정 — 학습 데이터 카나리 · 보호 코퍼스 · 게이트 기준", "D2-05 settings — training canaries · protected corpus · gate limits")} />
      </div>
    </>
  );
}
