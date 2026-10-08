// 성공 지표 (원본 PRD §15.1 · PRD.md §5) — 커버리지·품질·성능·도입·운영 KPI 12종 실측을 1단계·정상 운영 목표와 비교. 핵심 = 차단 모드 전환율.
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { t as tk, tr } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { snapshotNow } from "./actions";

const GROUP: Record<string, [string, string]> = { coverage: ["커버리지", "Coverage"], quality: ["품질", "Quality"], performance: ["성능", "Performance"],
  adoption: ["도입", "Adoption"], operations: ["운영", "Operations"] };
const ST: Record<string, [string, string, string]> = { met: ["충족", "met", "var(--verdict-allow)"], missed: ["미달", "missed", "var(--verdict-block)"] };

function target(v: unknown, unit: string, way: string) {
  if (v == null) return "—";
  if (typeof v === "string") return v;
  return `${way === "lower" ? "≤" : "≥"} ${v}${unit === "/10" ? "/10" : unit === "%" ? "%" : ` ${unit}`}`;
}

export default async function Success({ searchParams }: { searchParams: Promise<{ msg?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const { msg } = await searchParams;
  const { data: r, error } = await safe(api("/v1/metrics/success"), null as any);
  const st = (s: string | null) => (s ? <b style={{ color: ST[s][2] }}>{tr(lang, ST[s][0], ST[s][1])}</b> : <span className="text-muted">{tr(lang, "측정 전", "not measured")}</span>);
  const items: any[] = r?.items ?? [];
  const key = items.find((i) => i.id === r?.keyMetric);
  return (
    <>
      <PageHeader crumb={`${tk(lang, "groupMain")} › ${tr(lang, "성공 지표", "Success metrics")}`} title={tr(lang, "성공 지표 — PRD §15.1", "Success metrics — PRD §15.1")}
        actions={can(user, "governance") ? <form action={snapshotNow}><button className="btn btn-secondary" data-testid="kpi-snapshot">{tr(lang, "지금 기록 (원장 검증 포함)", "Record now (incl. ledger verification)")}</button></form> : undefined} />
      {msg && <div className="mb-3"><Banner tone={/^(실패|Failed)/.test(msg) ? "danger" : "info"}>{msg}</Banner></div>}
      {error && <p className="text-sm text-red-600">{error}</p>}
      {key && (
        <div className="mb-3" data-testid="key-metric"><Banner tone={key.status === "met" ? "info" : "warn"}>
          {tr(lang, `핵심 지표 — 차단 모드 전환 비율 ${key.display ?? "—"}${key.value != null ? ` (${key.value}%)` : ""} · 관측만 하는 설치는 방어가 아니다. 낮으면 원인은 거의 항상 오탐`,
            `Key metric — blocking-mode conversion ${key.display ?? "—"}${key.value != null ? ` (${key.value}%)` : ""} · an observe-only install is not a defence; when it is low the cause is almost always false positives`)}</Banner></div>
      )}
      {r && (
        <div className="mb-3 flex flex-wrap gap-2 text-xs" data-testid="kpi-summary">
          <Chip tone="primary">{tr(lang, `측정 ${r.summary.measured}/${r.summary.total}`, `measured ${r.summary.measured}/${r.summary.total}`)}</Chip>
          <Chip>{tr(lang, `1단계 목표 충족 ${r.summary.stage1Met}`, `stage-1 targets met ${r.summary.stage1Met}`)}</Chip>
          <Chip>{tr(lang, `정상 운영 목표 충족 ${r.summary.targetMet}`, `steady-state targets met ${r.summary.targetMet}`)}</Chip>
          <span className="text-muted">{fmtTime(r.generatedAt)}{r.tenant ? ` · ${r.tenant}` : ""}</span>
        </div>
      )}
      <section className="card overflow-hidden text-sm" data-testid="kpi-table">
        <table className="grid-table text-xs">
          <thead><tr><th>{tr(lang, "구분", "Group")}</th><th>{tr(lang, "지표", "Metric")}</th><th>{tr(lang, "현재", "Now")}</th><th>{tr(lang, "1단계 목표", "Stage-1 target")}</th><th /><th>{tr(lang, "정상 운영 목표", "Steady-state target")}</th><th /><th>{tr(lang, "추세", "Trend")}</th><th>{tr(lang, "측정 방법", "Method")}</th></tr></thead>
          <tbody>{items.map((i) => {
            const tl = (r.trend?.[i.id] ?? []).filter((x: any) => x.value != null).slice(-14);
            const max = Math.max(1, ...tl.map((x: any) => Math.abs(x.value)));
            return (
              <tr key={i.id} data-kpi={i.id} style={i.id === r.keyMetric ? { background: "var(--primary-soft, #EEF0FD)" } : undefined}>
                <td className="text-muted">{tr(lang, ...GROUP[i.group])}</td>
                <td><b>{tr(lang, i.nameKo, i.nameEn)}</b></td>
                <td className="mono">{i.display ?? "—"}{i.value != null && i.unit === "%" && !String(i.display).includes("%") ? <span className="text-muted"> ({i.value}%)</span> : null}</td>
                <td>{target(i.stage1Target, i.unit, i.direction)}</td><td>{st(i.stage1)}</td>
                <td>{target(i.target, i.unit, i.direction)}</td><td>{st(i.status)}</td>
                <td><div className="flex h-5 items-end gap-0.5">{tl.length === 0 ? <span className="text-muted">—</span> : tl.map((x: any, k: number) => (
                  <span key={k} title={`${fmtTime(x.at)} · ${x.value}`} className="w-1.5 rounded-t bg-primary" style={{ height: `${Math.max(8, (Math.abs(x.value) / max) * 100)}%` }} />))}</div></td>
                <td className="text-muted">{tr(lang, i.methodKo, i.methodEn)}
                  {i.id === "coverage" && i.detail?.p0 ? ` · P0 ${i.detail.p0}` : ""}
                  {i.id === "miss-rate" && i.detail?.corpus ? ` · ${i.detail.corpus}${i.detail.source ? ` (${i.detail.source})` : ""}` : ""}
                  {i.id === "fp-rate" && i.detail?.samples ? ` · ${i.detail.samples}${tr(lang, "건", "")}` : ""}
                  {i.id === "block-conversion" && i.detail?.observeOnly?.length ? ` · ${tr(lang, "관측만", "observe-only")}: ${i.detail.observeOnly.join(", ")}` : ""}
                  {i.id === "integrity" && i.value == null ? ` · ${tr(lang, "스냅샷 전 — '지금 기록' 또는 worker 일 1회", "no snapshot yet — 'Record now' or the daily worker")}` : ""}
                </td>
              </tr>
            );
          })}</tbody>
        </table>
      </section>
      <p className="mt-2 text-xs text-muted">{tr(lang, "값은 이 설치의 실데이터다. 골든셋·코퍼스가 합성 표본이면 낙관적일 수 있다 — 공개 코퍼스는 관측·SLO 화면에서 폐쇄망 파일로 반입해 측정한다. 목표: 원본 PRD §15.1.",
        "Values come from this installation's own data. Synthetic golden sets and corpora can be optimistic — import public corpora as offline files on the observability / SLO screen. Targets: source PRD §15.1.")}</p>
    </>
  );
}
