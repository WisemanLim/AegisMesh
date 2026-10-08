// SCR-Q05 관측 파이프라인·마스킹 설정 · SCR-Q04 SLO·비용·오탐 예산.
import Link from "next/link";
import { Banner, Chip } from "@/components/Badges";
import { MaskTester } from "@/components/MaskTester";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { t, tr, LX } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";

import { L } from "@/lib/i18n";

const SIG: Record<string, string> = { traces: "추적", metrics: "지표", logs: "로그" };

export default async function Observability() {
  const { lang } = await prefs();
  const user = await me();
  const { data: o, error } = await safe(api("/v1/observability"), null as any);
  const { data: dr } = await safe(api("/v1/observability/dr"), null as any);
  const { data: tl } = await safe(api("/v1/observability/tls"), null as any);
  const { data: km } = await safe(api("/v1/observability/kms"), null as any);
  if (!o) return <><PageHeader crumb={t(lang, "groupOpsRt")} title={tr(lang, "관측", "Observability")} /><Banner tone="danger">{error}</Banner></>;
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupOpsRt")} › ${t(lang, "observability")}`} title={tr(lang, "관측 파이프라인 · 마스킹 · SLO·오탐 예산", "Telemetry pipeline · masking · SLO & FP budget")} />
      {!o.enabled && <div className="mb-3"><Banner tone="warn">{L(lang, "OTEL_ENDPOINT 미설정 — 내보내기 비활성 (D10-07 경보)")}</Banner></div>}
      <section className="card mb-4 p-4 text-sm" data-testid="pipeline">
        <h2 className="mb-2 font-semibold">{L(lang, "파이프라인 (OpenTelemetry · ")}{LX(lang, o.protocol)}) — {LX(lang, o.service ?? "—")} → <span className="mono">{LX(lang, o.endpoint ?? "—")}</span></h2>
        <div className="grid grid-cols-3 gap-3">
          {Object.entries(o.pipeline).map(([sig, p]: [string, any]) => (
            <div key={sig} className="rounded border border-line p-3">
              <div className="font-semibold">{L(lang, SIG[sig] ?? sig)}</div>
              <div className="mt-1 text-xs">{L(lang, "수신 ")}<Chip>{p.receivers.join(", ")}</Chip>{L(lang, " → 처리 ")}{p.processors.map((x: string) => <Chip key={x} tone={x.startsWith("transform") ? "primary" : undefined}>{x}</Chip>)}{L(lang, " → 내보내기 ")}<Chip>{p.exporters.join(", ")}</Chip></div>
              <div className="mt-2 text-xs text-muted">{L(lang, "전송 성공 ")}{LX(lang, o.stats[sig].ok)}{L(lang, " · 실패 ")}{LX(lang, o.stats[sig].failed)}{L(lang, " · 항목 ")}{LX(lang, o.stats[sig].items)}{o.stats[sig].lastAt ? L(lang, " · 최근 {0}", fmtTime(new Date(o.stats[sig].lastAt * 1000).toISOString())) : ""}</div>
              {o.stats[sig].lastError && <div className="text-xs text-red-600">{LX(lang, o.stats[sig].lastError)}</div>}
            </div>
          ))}
        </div>
        <p className="mt-2 text-xs text-muted">{L(lang, "수집기 ")}{LX(lang, o.collector.image)}{L(lang, " · 설정 ")}{LX(lang, o.collector.config)}{L(lang, "(생성물) · 마스킹 문장 ")}{LX(lang, o.collector.statements)}{L(lang, "개 · ")}{LX(lang, o.payload.policy)}</p>
      </section>
      {o.evidencePipeline && (
        <section className="card mb-4 p-4 text-sm" data-testid="evidence-pipeline">
          <h2 className="mb-2 font-semibold">{L(lang, "증적 적재 (NFR-L5) — ")}{o.evidencePipeline.async ? L(lang, "비동기 묶음") : L(lang, "동기")} {o.evidencePipeline.degraded && <span style={{ color: "var(--verdict-block)" }}>{L(lang, "· 표본 적재 강등 중 (1/")}{LX(lang, o.evidencePipeline.sampleEvery)})</span>}</h2>
          <p className="text-xs">{L(lang, "대기 ")}{LX(lang, o.evidencePipeline.depth)}/{LX(lang, o.evidencePipeline.max)}{L(lang, " (최대 ")}{LX(lang, o.evidencePipeline.maxDepth)}{L(lang, ") · 적재 ")}{LX(lang, o.evidencePipeline.written)}{L(lang, " · 묶음 ")}{LX(lang, o.evidencePipeline.batches)}{L(lang, " (최근 ")}{LX(lang, o.evidencePipeline.lastBatch)}{L(lang, "건 ")}{LX(lang, o.evidencePipeline.lastBatchMs)}{L(lang, "ms) · 표본 제외 ")}{LX(lang, o.evidencePipeline.sampledOut)}{L(lang, " · 버림 ")}{LX(lang, o.evidencePipeline.dropped)}{L(lang, " · 실패 ")}{LX(lang, o.evidencePipeline.failed)}</p>
          <p className="mt-1 text-xs text-muted">{L(lang, "강등 ")}{Math.round(o.evidencePipeline.thresholds.degrade * 100)}{L(lang, "% · 복귀 ")}{Math.round(o.evidencePipeline.thresholds.recover * 100)}{L(lang, "% · 강등·복귀는 원장(evidence/pipeline)·알림 · ")}{LX(lang, o.evidencePipeline.process)}{L(lang, " · 바인딩 캐시 ")}{LX(lang, o.hotCache.ttlSec)}{L(lang, "초 (적중 ")}{LX(lang, o.hotCache.hits)}{L(lang, " · 무효화 ")}{LX(lang, o.hotCache.invalidations)})</p>
          {o.deepCheck && <p className="mt-1 text-xs" data-testid="deep-check">{o.deepCheck.enabled ? L(lang, "D1-03 깊은 검사(안전 분류 모델, 응답 후 경보) — 확인 {0} · 경보 {1} · 건너뜀 {2} · 실패 {3} · 대기 {4}/{5}", o.deepCheck.checked, o.deepCheck.alerts, o.deepCheck.skipped, o.deepCheck.failed, o.deepCheck.backlog, o.deepCheck.queueMax) : L(lang, "D1-03 깊은 검사 꺼짐 — make guard-up")}</p>}
        </section>
      )}
      {dr && (
        <section className="card mb-4 p-4 text-sm" data-testid="dr">
          <h2 className="mb-2 font-semibold">{L(lang, "재해 복구 (NFR-A5) — 목표 RTO {0}분 · RPO {1}분 · 원장 RPO 0", dr.targets.rtoMin, dr.targets.rpoMin)}</h2>
          {!dr.applicable ? <p className="text-xs text-muted">{LX(lang, dr.detail)}</p> : (
            <>
              <p className="text-xs">{L(lang, "역할 {0} · 원장 동기 복제 ", dr.role)}{dr.ledgerRpo0 ? <Chip tone="primary">{L(lang, "켜짐 ({0})", dr.syncStandbys.join(", "))}</Chip> : <span style={{ color: "var(--verdict-block)" }}>{L(lang, "꺼짐 — 원장 RPO 0 미보장")}</span>}</p>
              <ul className="mt-1 text-xs">
                {dr.standbys.map((x: any) => <li key={x.name} className="mono">{x.name} · {x.state} · {x.syncState} · {L(lang, "지연 {0} B", x.lagBytes ?? "—")}</li>)}
              </ul>
              <p className="mt-1 text-xs">{L(lang, "WAL 보관 {0}건 · 실패 {1} · 최근 {2} ({3}초 전) · 전환 주기 {4}초", dr.archive.archived, dr.archive.failed, dr.archive.lastWal ?? "—", dr.archive.ageSec ?? "—", dr.archive.timeoutSec)}</p>
            </>
          )}
          <p className="mt-1 text-xs text-muted">{dr.lastDrill ? L(lang, "최근 훈련 {0} · {1} · RTO {2}초 · {3}", dr.lastDrill.ref, dr.lastDrill.ok ? L(lang, "통과") : L(lang, "실패"), dr.lastDrill.rtoSec ?? "—", fmtTime(dr.lastDrill.at)) : L(lang, "최근 훈련 없음 — make db-restore-drill ENV=prod")}</p>
        </section>
      )}
      {tl && (
        <section className="card mb-4 p-4 text-sm" data-testid="tls">
          <h2 className="mb-2 font-semibold">{L(lang, "내부 상호 TLS (NFR-D3) — ")}{tl.enabled ? L(lang, "켜짐") : L(lang, "꺼짐")}</h2>
          {!tl.enabled ? <p className="text-xs text-muted">{LX(lang, tl.detail)}</p> : (
            <p className="text-xs">{L(lang, "말단 인증서 {0} · {1}일 남음 · CA {2}일 남음 · 이 api 의 DB 연결 {3}", tl.leaf.subject, tl.leaf.daysLeft, tl.ca.daysLeft, tl.db ? (tl.db.ssl ? `TLS ${tl.db.sslmode}` : L(lang, "평문")) : "—")}</p>
          )}
          <ul className="mt-1 text-xs text-muted">
            {tl.segments.map((x: any) => <li key={`${x.from}-${x.to}`}><span className="mono">{x.from} → {x.to}</span> · {LX(lang, x.auth)}</li>)}
          </ul>
        </section>
      )}
      {km && (
        <section className="card mb-4 p-4 text-sm" data-testid="kms">
          <h2 className="mb-2 font-semibold">{L(lang, "저장 암호화 (NFR-D2) — KMS {0}", km.backend)}{km.builtinKek ? L(lang, " · KEK v{0}", km.builtinKek.current) : ""}{km.transitKey ? ` · transit ${km.transitKey}` : ""}</h2>
          <p className="text-xs">{L(lang, "최근 증적 {0}/{1}건 암호화 · 전체 원장 {2}건(추가 전용 — 암호화 전 기록은 보존기한 삭제로만 사라짐)", km.evidence.recent.encrypted, km.evidence.recent.rows, km.evidence.records)}</p>
          <ul className="mt-1 grid grid-cols-2 gap-x-4 text-xs">
            {Object.entries(km.tables).map(([k, v]: [string, any]) => <li key={k}><span className="mono">{k}</span> · {L(lang, "{0}/{1} 암호화", v.encrypted, v.rows)} {Object.keys(v.byKek).length ? `(${Object.keys(v.byKek).join(", ")})` : ""}</li>)}
          </ul>
          <p className="mt-1 text-xs text-muted">{L(lang, "서명 키·세션 비밀 파일 포장: {0}", Object.entries(km.keyFiles).map(([k, v]) => `${k} ${v === null ? "—" : v ? "✓" : "✗"}`).join(" · "))}</p>
        </section>
      )}
      <div className="grid grid-cols-2 gap-4">
        <section className="card p-4 text-sm">
          <h2 className="mb-2 font-semibold">{L(lang, "수집 단계 마스킹 규칙 (")}{o.masking.length}) — observability/masking.yaml</h2>
          <table className="grid-table text-xs"><thead><tr><th>{L(lang, "규칙")}</th><th>{L(lang, "정규식")}</th><th>{L(lang, "치환")}</th></tr></thead>
            <tbody>{o.masking.map((r: any) => <tr key={r.name}><td>{LX(lang, r.title)}</td><td className="mono break-all">{LX(lang, r.pattern)}</td><td className="mono">{LX(lang, r.replacement)}</td></tr>)}</tbody></table>
          <h3 className="mb-1 mt-3 font-semibold">{L(lang, "시험 로그로 확인 후 배포")}</h3>
          <MaskTester canSend={can(user, "governance")} />
        </section>
        <section className="card p-4 text-sm" data-testid="slo">
          <h2 className="mb-2 font-semibold">{L(lang, "SLO · 방어 비용 (24시간, ")}{LX(lang, o.slo.records24h)}{L(lang, "건)")}</h2>
          <table className="grid-table text-xs"><thead><tr><th>{L(lang, "관문")}</th><th>p95</th><th>{L(lang, "예산")}</th><th>{L(lang, "소진")}</th><th>{L(lang, "판정")}</th></tr></thead>
            <tbody>{Object.entries(o.slo.gates).map(([g, x]: [string, any]) => (
              <tr key={g}><td>{g}</td><td>{LX(lang, x.p95Ms)}ms</td><td>{LX(lang, x.budgetMs)}ms</td><td>{Math.round(x.burn * 100)}%</td><td>{x.breach ? <b style={{ color: "var(--verdict-block)" }}>{L(lang, "초과")}</b> : x.records ? L(lang, "정상") : L(lang, "관측 없음")}</td></tr>
            ))}</tbody></table>
          <p className="mt-1 text-xs text-muted">{L(lang, "요청당 평균 관문 지연(방어 비용) ")}{LX(lang, o.slo.avgGateOverheadMs)}ms</p>
          <h3 className="mb-1 mt-3 font-semibold">{L(lang, "오탐 예산 (에이전트별 FP ≤ ")}{o.slo.fpBudget * 100}{L(lang, "%) — 레드팀 ")}{o.slo.redteamAt ? fmtTime(o.slo.redteamAt) : L(lang, "기록 없음")} · <Link className="text-primary" href="/redteam">{L(lang, "레드팀")}</Link></h3>
          <p className="text-xs">{L(lang, "예산 초과 ")}{o.slo.fpOverBudget.join(", ") || L(lang, "없음")}{L(lang, " · 회귀 ")}{o.slo.regressions.join(", ") || L(lang, "없음")}{L(lang, " · 경보 전용 ")}{o.alertOnly.join(", ") || L(lang, "없음")}</p>
          <table className="grid-table mt-1 text-xs"><thead><tr><th>{L(lang, "에이전트")}</th><th>FP</th><th>{L(lang, "예산 소진")}</th><th>{L(lang, "탐지율 / 기준선")}</th></tr></thead>
            <tbody>{o.slo.fp.slice(0, 8).map((x: any) => <tr key={x.agent}><td>{LX(lang, x.agent)}</td><td>{(x.fpRate * 100).toFixed(2)}%</td><td>{Math.round(x.consumed * 100)}%</td><td>{LX(lang, x.detectionRate)} / {LX(lang, x.baseline)}{x.regression ? " ⚠" : ""}</td></tr>)}</tbody></table>
          <h3 className="mb-1 mt-3 font-semibold">{L(lang, "자동 대응 규칙")}</h3>
          <ul className="list-disc pl-4 text-xs">{o.rollbackRules.map((r: string) => <li key={r}>{L(lang, r)}</li>)}</ul>
        </section>
      </div>
    </>
  );
}
