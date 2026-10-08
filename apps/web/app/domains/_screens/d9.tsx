// D9 인프라 상세 화면 — SCR-M02 클라우드·IaC·DB 노출, SCR-M03 런타임·엔드포인트 침해 대응, SCR-M04 암호화·네트워크·DDoS.
import Link from "next/link";
import { Kpi, VerdictBadge } from "@/components/Badges";
import { tr, LX } from "@/lib/i18n";
import { ArtifactBoard, loadBoard } from "./artifacts";
import { AgentStrip, DetailHeader, type ScreenProps, SettingsCard } from "./common";

const latest = (x: any, kind: string) => (x?.targets ?? []).filter((t: any) => t.kind === kind).at(-1)?.artifact;

export async function Posture({ lang, user, d, screen, sp }: ScreenProps) {
  const x = await loadBoard("posture");
  const db = latest(x, "db_accounts");
  return (
    <>
      <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />
      <AgentStrip lang={lang} ids={["d9-01", "d9-04"]} />
      <div className="mb-4 grid grid-cols-2 gap-4">
        <section className="card space-y-2 p-4 text-sm"><h2 className="font-semibold">{tr(lang, "연결 · 자동 차단 정책", "Connections · auto-block policy")}</h2>
          <p className="text-xs">{tr(lang, `대상 ${x?.targets.length ?? 0}개 (클라우드 상태 점검·IaC·DB 계정) — 외부 콘솔은 모사하지 않는다. 결과를 prowler·checkov·steampipe 등에서 이 모양으로 넣는다.`, `${x?.targets.length ?? 0} targets (cloud posture · IaC · DB accounts) — external consoles are not replicated; submit prowler · checkov · steampipe results in this shape.`)}</p>
          <ul className="list-disc space-y-1 pl-5 text-xs"><li>{tr(lang, "공개 버킷·IAM * 정책·관리 포트 전체 공개 = 차단 판정 → 격리 목록·사건", "Public bucket · IAM * policy · admin port open to the world = block → quarantine list · incident")}</li>
            <li>{tr(lang, "IaC 실패 = 병합 차단(CI 가 판정을 게이트로 사용)", "IaC failure = merge blocked (CI uses the verdict as a gate)")}</li>
            <li>{tr(lang, "예외는 위험 등록부 수용 결정(책임자·기한)", "Exceptions = risk-register acceptance (owner · deadline)")} · <Link className="text-primary" href="/risks">{tr(lang, "위험 등록부 ›", "Risk register ›")}</Link></li></ul></section>
        <section className="card overflow-hidden text-sm" data-testid="db-accounts"><h2 className="p-3 font-semibold">{tr(lang, "DB 접근 게이트웨이 — 에이전트 DB 계정 (AG-D9-04)", "DB access gateway — agent DB accounts (AG-D9-04)")}</h2>
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "계정", "Account")}</th><th>{tr(lang, "사용", "Used by")}</th><th>{tr(lang, "권한", "Privileges")}</th><th>{tr(lang, "경유", "Path")}</th><th>{tr(lang, "쿼리 감사", "Audit")}</th></tr></thead>
            <tbody>{!db ? <tr><td colSpan={5} className="text-muted">{tr(lang, "db_accounts 대상 없음", "No db_accounts target")}</td></tr> : db.accounts.map((a: any) => (
              <tr key={a.user}><td className="mono">{a.user}</td><td>{a.agent ?? a.usedBy}</td><td>{a.privileges.join(", ")}</td><td style={{ color: a.viaGateway ? "var(--verdict-allow)" : "var(--verdict-block)" }}>{a.viaGateway ? "GW ✓" : tr(lang, "직접 ✗", "direct ✗")}</td><td>{a.queryAudit ? "✓" : "✗"}</td></tr>))}</tbody></table>
          <p className="p-3 text-xs text-muted">{tr(lang, "직접 접속 차단·게이트웨이 경유만 · 스키마 변경은 승인 워크플로", "Direct connections blocked · gateway only · schema changes via approval workflow")}</p></section>
      </div>
      {x && <ArtifactBoard lang={lang} user={user} x={x} back="/domains/d9/posture" decisions={["retest", "reject"]} />}
    </>
  );
}

export async function Runtime({ lang, user, d, screen, sp }: ScreenProps) {
  const x = await loadBoard("runtime");
  const ep = latest(x, "endpoint_posture");
  const steps = [["탐지 — 커널 이벤트(eBPF) 결과 제출", "Detect — submit kernel-event (eBPF) results"], ["격리 — 차단 판정 호스트는 격리 목록(관문 즉시 차단)", "Isolate — blocked hosts go to the quarantine list (gate blocks at once)"],
    ["신원 회수 — SVID 즉시 회전·동적 시크릿 회수", "Revoke identity — rotate SVIDs and revoke dynamic secrets"], ["사건 — 상관 분석 묶음·스냅샷 보존(외부)", "Incident — correlated bundle · snapshot kept (external)"], ["복구 — 재배포 후 격리 해제(2인 승인)", "Recover — release after redeploy (two approvals)"]];
  return (
    <>
      <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />
      <AgentStrip lang={lang} ids={["d9-02", "d9-05"]} />
      <div className="mb-4 grid grid-cols-2 gap-4">
        <section className="card space-y-2 p-4 text-sm" data-testid="ir-flow"><h2 className="font-semibold">{tr(lang, "침해 대응 흐름", "Compromise response flow")}</h2>
          <ol className="space-y-1 text-xs">{steps.map(([ko, en], i) => <li key={i} className="flex gap-2"><span className="grid h-5 w-5 place-items-center rounded-full bg-navy text-[10px] text-white">{i + 1}</span>{tr(lang, ko, en)}</li>)}</ol>
          <p className="text-xs">{tr(lang, "격리 중 호스트", "Quarantined hosts")}: {(x?.quarantine ?? []).filter((q: any) => q.kind === "host").map((q: any) => q.value).join(", ") || "—"} · <Link className="text-primary" href="/admin/identity">{tr(lang, "SVID 즉시 회전 ›", "Rotate SVIDs now ›")}</Link> · <Link className="text-primary" href="/incidents">{tr(lang, "사건 ›", "Incidents ›")}</Link></p></section>
        <section className="card overflow-hidden text-sm" data-testid="endpoints"><h2 className="p-3 font-semibold">{tr(lang, "엔드포인트 · 러너·워크스테이션 (AG-D9-05)", "Endpoints · runners & workstations (AG-D9-05)")}</h2>
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "호스트", "Host")}</th><th>EDR</th><th>{tr(lang, "무결성", "Integrity")}</th><th>{tr(lang, "평문 자격증명", "Plaintext creds")}</th><th>{tr(lang, "하드웨어 키", "HW key")}</th><th>{tr(lang, "세션", "Session")}</th></tr></thead>
            <tbody>{!ep ? <tr><td colSpan={6} className="text-muted">{tr(lang, "endpoint_posture 대상 없음", "No endpoint_posture target")}</td></tr> : ep.hosts.map((h: any) => (
              <tr key={h.name}><td className="mono">{h.name}</td><td>{h.edr ? "✓" : "✗"}</td><td style={{ color: h.integrityOk ? undefined : "var(--verdict-block)" }}>{h.integrityOk ? "✓" : tr(lang, "✗ 변경", "✗ changed")}</td><td>{h.plaintextCredentials ?? 0}</td><td>{h.hwKey ? "✓" : "✗"}</td><td>{h.sessionHours}h</td></tr>))}</tbody></table>
          <p className="p-3 text-xs text-muted">{tr(lang, "무결성 실패 시 즉시 세션 만료(MSG-030) · 자격증명은 하드웨어 보관 · 세션 최대 시간은 d9-05 설정", "Integrity failure → session expires at once (MSG-030) · credentials in hardware · max session in d9-05 settings")}</p></section>
      </div>
      {x && <ArtifactBoard lang={lang} user={user} x={x} back="/domains/d9/runtime" decisions={["release", "retest"]} title={tr(lang, "런타임 이벤트 · 엔드포인트 대상", "Runtime events · endpoint targets")} />}
      <div className="mt-4 grid grid-cols-2 gap-4">
        <SettingsCard lang={lang} user={user} id="d9-02" title={tr(lang, "탐지 규칙 — 의심 포트·차단 IP (d9-02)", "Detection rules — suspicious ports · blocked IPs (d9-02)")} />
        <SettingsCard lang={lang} user={user} id="d9-05" title={tr(lang, "엔드포인트 정책 — 세션·하드웨어 키 (d9-05)", "Endpoint policy — session · hardware key (d9-05)")} />
      </div>
    </>
  );
}

export async function Network({ lang, user, d, screen, sp }: ScreenProps) {
  const x = await loadBoard("network");
  const ci = latest(x, "crypto_inventory"), np = latest(x, "network_policy"), ts = latest(x, "traffic_stats");
  const eps = ci?.endpoints ?? [];
  const mtls = eps.length ? eps.filter((e: any) => e.mtls).length / eps.length : null;
  return (
    <>
      <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />
      <AgentStrip lang={lang} ids={["d9-03", "d9-06", "d9-07"]} />
      <div className="mb-4 grid grid-cols-3 gap-4" data-testid="network-cols">
        <section className="card space-y-2 p-4 text-sm"><h2 className="font-semibold">{tr(lang, "암호화 (d9-03)", "Encryption (d9-03)")}</h2>
          <Kpi label={tr(lang, "내부 구간 mTLS 적용률", "Internal mTLS coverage")} value={mtls == null ? "—" : `${Math.round(mtls * 100)}%`} sub={tr(lang, `평문 링크 ${eps.filter((e: any) => !e.tls).length}`, `${eps.filter((e: any) => !e.tls).length} plaintext links`)} accent={mtls != null && mtls < 1 ? "#9d6105" : "var(--verdict-allow)"} />
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "인증서", "Certificate")}</th><th>{tr(lang, "만료", "Expires")}</th><th>mTLS</th></tr></thead>
            <tbody>{eps.map((e: any) => <tr key={e.name}><td className="mono">{e.name}</td><td style={{ color: e.certExpiresInDays <= 7 ? "var(--verdict-block)" : e.certExpiresInDays <= 14 ? "#9d6105" : undefined }}>{e.certExpiresInDays}{tr(lang, "일", "d")}</td><td>{e.mtls ? "✓" : "✗"}</td></tr>)}</tbody></table>
          <ul className="text-xs">{(ci?.stores ?? []).map((s: any) => <li key={s.name}>{s.encrypted ? "✓" : <b style={{ color: "var(--verdict-block)" }}>✗</b>} {s.name}</li>)}</ul></section>
        <section className="card space-y-2 p-4 text-sm"><h2 className="font-semibold">{tr(lang, "네트워크 (d9-06)", "Network (d9-06)")}</h2>
          <p className="text-xs">{tr(lang, `이그레스 기본값 ${np?.egressDefault ?? "—"} · 상호 인증 ${np?.mtls ? "필수 ✓" : "—"}`, `egress default ${np?.egressDefault ?? "—"} · mutual auth ${np?.mtls ? "required ✓" : "—"}`)}</p>
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "흐름", "Flow")}</th><th>TLS</th><th>mTLS</th><th>{tr(lang, "외부", "External")}</th></tr></thead>
            <tbody>{(np?.flows ?? []).map((f: any, i: number) => <tr key={i}><td className="mono">{f.src} → {f.dst}:{f.port}</td><td>{f.tls ? "✓" : "✗"}</td><td>{f.mtls === false ? <b style={{ color: "var(--verdict-block)" }}>✗</b> : "✓"}</td><td>{f.external ? "✓" : ""}</td></tr>)}</tbody></table>
          <p className="text-xs text-muted">{tr(lang, "허용목록 외 이그레스 차단 · 추가는 정책 배포 경유 · 흐름 관측(hubble 등) 결과를 network_policy 로", "Egress outside the allowlist blocked · additions via policy deploy · submit flow observations (e.g. hubble) as network_policy")}</p></section>
        <section className="card space-y-2 p-4 text-sm"><h2 className="font-semibold">{tr(lang, "서비스 거부 (d9-07)", "Denial of service (d9-07)")}</h2>
          <Kpi label={tr(lang, "게이트웨이 rps", "Gateway rps")} value={ts?.rps ?? "—"} sub={ts ? tr(lang, `기준 ${ts.baselineRps} · ${Math.round(ts.rps / Math.max(1, ts.baselineRps) * 10) / 10}배`, `baseline ${ts.baselineRps} · ${Math.round(ts.rps / Math.max(1, ts.baselineRps) * 10) / 10}×`) : undefined} accent={ts && ts.rps > 5 * ts.baselineRps ? "var(--verdict-block)" : "var(--primary)"} />
          <dl className="grid grid-cols-[110px_1fr] gap-y-1 text-xs"><dt className="text-muted">{tr(lang, "상위 클라이언트", "Top client")}</dt><dd>{ts ? `${ts.topClient} · ${Math.round(ts.topClientShare * 100)}%` : "—"}</dd>
            <dt className="text-muted">{tr(lang, "레이트리밋", "Rate limit")}</dt><dd>{ts ? (ts.rateLimit ? "✓" : "✗") : "—"}</dd><dt className="text-muted">{tr(lang, "대기열", "Queue")}</dt><dd>{ts?.queueDepth ?? "—"}</dd>
            <dt className="text-muted">{tr(lang, "확장 한계", "Autoscale max")}</dt><dd>{ts?.autoscaleMax ?? "—"}</dd></dl>
          <p className="text-xs text-muted">{tr(lang, "평판 차단·우선순위 대기열(승인·보안 > 업무 > 배치)은 엣지(crowdsec·envoy) 몫 — 지표를 traffic_stats 로", "Reputation blocking and priority queues (approvals/security > business > batch) belong to the edge (crowdsec · envoy) — submit metrics as traffic_stats")}</p></section>
      </div>
      {x && <ArtifactBoard lang={lang} user={user} x={x} back="/domains/d9/network" decisions={["retest", "reject"]} />}
      <div className="mt-4 grid grid-cols-2 gap-4">
        <SettingsCard lang={lang} user={user} id="d9-03" title={tr(lang, "mTLS 필수 · 인증서 만료 경고 (d9-03)", "Require mTLS · cert expiry warning (d9-03)")} />
        <SettingsCard lang={lang} user={user} id="d9-07" title={tr(lang, "급증 배율 · 단일 클라이언트 비중 (d9-07)", "Surge factor · single-client share (d9-07)")} />
      </div>
    </>
  );
}
