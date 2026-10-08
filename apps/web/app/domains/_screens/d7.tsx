// D7 공급망 상세 화면 — SCR-K02 서드파티 도구·플러그인 심사, SCR-K03 SBOM·의존성·패키지 백도어, SCR-K04 데이터셋·모델·API 공급자 무결성.
import { Banner, Kpi, VerdictBadge } from "@/components/Badges";
import { api, safe } from "@/lib/api";
import { tr, LX } from "@/lib/i18n";
import { ArtifactBoard, loadBoard } from "./artifacts";
import { AgentStrip, DetailHeader, type ScreenProps, SettingsCard } from "./common";

export async function Review({ lang, user, d, screen, sp }: ScreenProps) {
  const [x, sb] = await Promise.all([loadBoard("review"), safe(api("/v1/domains/d3/sandbox"), null as any)]);
  const l2 = sb.data?.sandbox?.pools?.find((p: any) => p.level === "L2");
  const st = (t: any) => t.decision?.decision ?? (t.lastVerdict === "block" ? "blocked" : t.lastVerdict ? "reviewing" : "queued");
  const counts = (x?.targets ?? []).reduce((m: Record<string, number>, t: any) => ({ ...m, [st(t)]: (m[st(t)] ?? 0) + 1 }), {});
  return (
    <>
      <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />
      <AgentStrip lang={lang} ids={["d7-01", "d7-04"]} />
      <div className="mb-4 grid grid-cols-[1fr_420px] gap-4">
        <section className="card space-y-2 p-4 text-sm" data-testid="review-pipeline">
          <h2 className="font-semibold">{tr(lang, "심사 단계 (등록 전 필수)", "Review stages (required before registration)")}</h2>
          <ol className="list-decimal space-y-1 pl-5 text-xs">
            <li>{tr(lang, "매니페스트·서명·출처 (d7-01) — 서명 없는 대상은 '등록 거부' 고정, 설치·기동 불가(MSG-005)", "Manifest · signature · source (d7-01) — unsigned targets are pinned to 'refused', cannot install or start (MSG-005)")}</li>
            <li>{tr(lang, "정적 심사 — 도구 설명·스키마의 숨은 지시(프롬프트 표면 스캔, d7-04)", "Static review — hidden instructions in tool descriptions/schemas (prompt-surface scan, d7-04)")}</li>
            <li>{l2?.available ? tr(lang, "동적 심사 — L2 샌드박스", "Dynamic review — L2 sandbox") : <span style={{ color: "#9d6105" }}>{tr(lang, "동적 심사 — L2 런타임 없음: 보류(격리 등급 낮춤 없음, MSG-006)", "Dynamic review — no L2 runtime: held (never downgraded, MSG-006)")}</span>}</li>
            <li>{tr(lang, "권한 선언 대조 — 선언 대 실행 중 요청(미선언 권한 = 차단, 미사용 = 축소 권고)", "Permission check — declared vs requested at runtime (undeclared = block, unused = shrink)")}</li>
            <li>{tr(lang, "결정 — 승인(쓰기·네트워크 권한은 2인)·조건부 승인·반려·재시험, 레지스트리 반영·원장 기록", "Decision — approve (write/network permissions need two people) · conditional · reject · retest; recorded in the registry and ledger")}</li>
          </ol>
        </section>
        <section className="card p-4 text-sm"><h2 className="mb-2 font-semibold">{tr(lang, "심사 대기함 상태", "Queue status")}</h2>
          <div className="grid grid-cols-2 gap-2">{Object.entries(counts).map(([k, v]) => <Kpi key={k} label={k} value={String(v)} accent={k === "blocked" || k === "reject" ? "var(--verdict-block)" : "var(--primary)"} />)}</div>
          {Object.keys(counts).length === 0 && <p className="text-xs text-muted">{tr(lang, "대기 없음", "Empty")}</p>}</section>
      </div>
      {x ? <ArtifactBoard lang={lang} user={user} x={x} back="/domains/d7/review" decisions={["approve", "conditional", "reject", "retest"]} title={tr(lang, "심사 대기함 — MCP·플러그인·스킬·도구", "Review queue — MCP · plugin · skill · tool")} /> : <Banner tone="danger">—</Banner>}
    </>
  );
}

export async function Sbom({ lang, user, d, screen, sp }: ScreenProps) {
  const x = await loadBoard("sbom");
  const sbomT = x?.targets.filter((t) => t.kind === "sbom").at(-1);
  const sbomS = x?.scans.find((r) => r.kind === "sbom");
  const vulns = (sbomS?.hits ?? []).flatMap((h: any) => h.notes.map(([loc, n]: [string, string]) => ({ loc, n, sev: /\((critical|high)\)/.exec(n)?.[1] ?? "medium" })));
  const pkg = x?.scans.filter((r) => r.kind === "package" && r.verdict !== "allow") ?? [];
  return (
    <>
      <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />
      <AgentStrip lang={lang} ids={["d7-02", "d7-03"]} />
      <div className="mb-4 grid grid-cols-4 gap-3" data-testid="sbom-kpis">
        <Kpi label={tr(lang, "구성요소", "Components")} value={sbomT?.artifact?.components?.length ?? "—"} sub={sbomT?.name} accent="var(--primary)" />
        <Kpi label="critical · high" value={`${vulns.filter((v: any) => v.sev === "critical").length} · ${vulns.filter((v: any) => v.sev === "high").length}`} accent="var(--verdict-block)" />
        <Kpi label={tr(lang, "빌드 게이트", "Build gate")} value={sbomS ? (sbomS.verdict === "block" ? tr(lang, "차단", "blocked") : tr(lang, "통과", "pass")) : "—"} accent={sbomS?.verdict === "block" ? "var(--verdict-block)" : "var(--verdict-allow)"} />
        <Kpi label={tr(lang, "백도어 의심 패키지", "Suspected backdoor packages")} value={pkg.length} accent={pkg.length ? "var(--verdict-block)" : "var(--verdict-allow)"} />
      </div>
      <div className="mb-4 grid grid-cols-2 gap-4">
        <section className="card overflow-hidden text-sm" data-testid="vulns">
          <h2 className="p-3 font-semibold">{tr(lang, "취약 구성요소 (최근 SBOM 점검)", "Vulnerable components (latest SBOM scan)")}</h2>
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "패키지@버전", "Package@version")}</th><th>{tr(lang, "권고 · 심각도 · 수정 버전", "Advisory · severity · fix")}</th><th>{tr(lang, "조치", "Action")}</th></tr></thead>
            <tbody>{vulns.length === 0 ? <tr><td colSpan={3} className="text-muted">—</td></tr> : vulns.map((v: any, i: number) => (
              <tr key={i}><td className="mono">{v.loc?.replace("component:", "")}</td><td>{LX(lang, v.n)}</td><td style={{ color: v.sev === "medium" ? "#9d6105" : "var(--verdict-block)" }}>{v.sev === "medium" ? tr(lang, "경보", "alert") : tr(lang, "빌드 차단", "block build")}</td></tr>))}</tbody></table>
          <p className="p-3 text-xs text-muted">{tr(lang, "규칙: critical·high → 빌드 차단(수정 버전 안내), medium 경보. 권고 DB = d7-02 advisories(OSV 요약) · 폐쇄망은 반입 스냅샷. 예외(수용)는 위험 등록부 경유", "Rule: critical/high → block the build (fix version shown); medium → alert. Advisory DB = d7-02 advisories (OSV summary) · offline: imported snapshot. Exceptions (acceptance) go through the risk register")}</p>
        </section>
        <section className="card space-y-2 p-4 text-sm" data-testid="cli-gate">
          <h2 className="font-semibold">{tr(lang, "CLI 빌드 게이트 (CI 그대로 사용)", "CLI build gate (use as-is in CI)")}</h2>
          <pre className="mono whitespace-pre-wrap rounded bg-[#f3f4f8] p-2 text-xs" lang="ko" data-user>{`$ aegis sbom check sbom.cdx.json --advisories osv-snapshot.json --fail-on high
✗ 3 components · 2 vulnerable · worst critical (fail-on high) → exit 1
  pyyaml@5.3  CVE-2020-14343 (critical) … · 수정 5.4`}</pre>
          <p className="text-xs text-muted">{tr(lang, "CycloneDX·SPDX(JSON) 입력, 네트워크 없이 d7-02 로 판정 — 플랫폼과 같은 규칙", "CycloneDX or SPDX (JSON) input, judged by d7-02 offline — same rules as the platform")}</p>
          <h2 className="pt-2 font-semibold">{tr(lang, "백도어 의심 패키지 (d7-03 휴리스틱)", "Suspected backdoor packages (d7-03 heuristics)")}</h2>
          <ul className="text-xs">{pkg.length === 0 ? <li className="text-muted">{tr(lang, "없음", "None")}</li> : pkg.slice(0, 6).map((r: any) => (
            <li key={r.seq}><VerdictBadge v={r.verdict} /> <span className="mono">{r.name}</span> — {r.hits.flatMap((h: any) => h.notes.map((n: any) => n[1])).join("; ")}</li>))}</ul>
          <p className="text-xs text-muted">{tr(lang, "설치 시 동적 관찰(L2) 런타임이 없으면 휴리스틱만 — 격리 유지, 허용은 2인 승인(허용 예외)", "Without an L2 runtime for install-time observation, heuristics only — stays quarantined; allowing needs two approvals (allow exception)")}</p>
        </section>
      </div>
      {x && <ArtifactBoard lang={lang} user={user} x={x} back="/domains/d7/sbom" decisions={["allow", "retest", "reject"]} title={tr(lang, "SBOM·패키지 대상", "SBOM · package targets")} />}
      <div className="mt-4 grid grid-cols-2 gap-4">
        <SettingsCard lang={lang} user={user} id="d7-02" title={tr(lang, "d7-02 — 취약점 권고 목록(OSV 요약)", "d7-02 — advisories (OSV summary)")} />
        <SettingsCard lang={lang} user={user} id="d7-03" title={tr(lang, "d7-03 — 인기 패키지(타이포스쿼팅 기준)", "d7-03 — popular packages (typosquat reference)")} />
      </div>
    </>
  );
}

export async function Integrity({ lang, user, d, screen, sp }: ScreenProps) {
  const x = await loadBoard("integrity");
  const col = (kind: string) => (x?.targets ?? []).filter((t) => t.kind === kind);
  const last = (kind: string, name: string) => x?.scans.find((r) => r.kind === kind && r.name === name);
  const COLS: [string, string, string, (a: any) => string][] = [
    ["dataset", "데이터셋 · RAG 코퍼스 (d7-05)", "Datasets · RAG corpora (d7-05)", (a) => `${a.version ?? ""} · ${a.contentHash === a.pinnedHash ? "hash ✓" : "hash ✗"} · ${a.changeApproved ? "approved" : "unapproved"} · ${a.rows ?? "?"}/${a.baselineRows ?? "?"}`],
    ["model", "모델 가중치 (d7-06)", "Model weights (d7-06)", (a) => `${a.format ?? ""} · ${a.signed && a.signatureValid ? "sig ✓" : "sig ✗"} · ${a.sha256 === a.expectedSha256 ? "sha ✓" : "sha ✗"}${(a.pickleGlobals ?? []).length ? ` · ${a.pickleGlobals.join(",")}` : ""}`],
    ["api_provider", "상위 API 공급자 (d7-07)", "Upstream API providers (d7-07)", (a) => `${a.host ?? ""} · ${a.pinnedFingerprint && a.pinnedFingerprint === a.presentedFingerprint ? "pin ✓" : "pin ✗"} · ${a.responseSignatureValid ? "resp sig ✓" : "resp sig ✗"} · ${a.attestation ? "in-toto ✓" : "in-toto —"}`],
  ];
  return (
    <>
      <DetailHeader lang={lang} d={d} screen={screen} msg={LX(lang, sp.msg)} />
      <AgentStrip lang={lang} ids={["d7-05", "d7-06", "d7-07"]} />
      <div className="mb-4 grid grid-cols-3 gap-4" data-testid="integrity-cols">
        {COLS.map(([kind, ko, en, fmt]) => (
          <section key={kind} className="card space-y-2 p-4 text-sm">
            <h2 className="font-semibold">{tr(lang, ko, en)}</h2>
            {col(kind).length === 0 ? <p className="text-xs text-muted">{tr(lang, "등록 대상 없음", "No targets")}</p> : col(kind).map((t) => {
              const r = last(kind, t.name);
              return (
                <div key={t.id} className="rounded border border-line p-2 text-xs">
                  <div className="flex items-center gap-2"><b className="mono">{t.name}</b>{t.lastVerdict && <VerdictBadge v={t.lastVerdict} />}</div>
                  <div className="text-muted">{fmt(t.artifact ?? {})}</div>
                  {r?.hits?.flatMap((h: any) => h.notes.map((n: any, i: number) => <div key={h.finding + i} style={{ color: "var(--verdict-block)" }}>{h.ruleId} · {LX(lang, n[1])}</div>))}
                  {t.decision && <div>{tr(lang, "결정", "Decision")}: {t.decision.decision} · {t.decision.by}</div>}
                </div>
              );
            })}
          </section>
        ))}
      </div>
      <p className="mb-3 text-xs text-muted">{tr(lang, "위반 → 로드 거부(서명·역직렬화)·연결 차단(핀 불일치)·색인 반영 보류(미승인 변경). 데이터셋 변경 승인·직전 버전 복원은 원장 기록, 핀 갱신은 2인 승인.", "Violations → refuse to load (signature · deserialization) · block connection (pin mismatch) · hold indexing (unapproved change). Dataset change approval and restore are ledgered; pin updates need two approvals.")}</p>
      {x && <ArtifactBoard lang={lang} user={user} x={x} back="/domains/d7/integrity" decisions={["accept-change", "restore", "pin-update", "retest", "reject"]} />}
      <div className="mt-4 grid grid-cols-3 gap-4">
        <SettingsCard lang={lang} user={user} id="d7-05" title="d7-05" />
        <SettingsCard lang={lang} user={user} id="d7-06" title="d7-06" />
        <SettingsCard lang={lang} user={user} id="d7-07" title={tr(lang, "d7-07 — 이그레스 허용 공급자", "d7-07 — egress allowlist")} />
      </div>
    </>
  );
}
