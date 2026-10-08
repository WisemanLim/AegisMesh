// SCR-B04 위험 지도 — 10분류 × 7항목 + 보강 10. 셀 = 에이전트 1종(DP1).
import Link from "next/link";
import { Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { standardChips } from "@/lib/format";
import { t, tr, nm, LX } from "@/lib/i18n";
import { cellLabel, counts, grid, type RiskItem } from "@/lib/riskmap";
import { prefs } from "@/lib/session";

import { L } from "@/lib/i18n";

// 칸 글자 대비 4.5:1 이상 (Epic 39) — 부분 차단·경보 전용은 연한 바탕 + 진한 글자로 '차단'·'관측' 과 구분
const STATE: Record<string, [string, string, string]> = {
  enforce: ["차단", "var(--verdict-block)", "#fff"],
  partial: ["부분 차단", "#f6caca", "#8f1d1d"],
  observe: ["관측·경보", "var(--verdict-alert)", "#fff"],
  alert_only: ["경보 전용", "#e4dbfa", "#4b2a99"],
  available: ["구현·미적용", "#ffffff", "var(--ink)"],
  stopped: ["강등·중지", "var(--verdict-approval)", "#fff"],
  missing: ["미구현", "var(--state-missing)", "#565e70"],
};

export default async function RiskMap({ searchParams }: { searchParams: Promise<{ item?: string }> }) {
  const { lang } = await prefs();
  const { item } = await searchParams;
  const { data, error } = await safe(api<{ items: RiskItem[] }>("/v1/risk-items"), { items: [] });
  const { rows, gaps } = grid(data.items, lang);
  const sel = data.items.find((i) => i.id === item);
  const agent = sel?.agent ? (await safe(api(`/v1/agents/${sel.agent}`), null as any)).data : null;
  const c = counts(data.items);
  const cell = (i: RiskItem) => {
    const [ko, bg, fg] = STATE[i.state] ?? STATE.missing;
    const label = L(lang, ko);
    return (
      <Link key={i.id} href={`/risk-map?item=${i.id}`} title={`${i.id} ${nm(lang, i)} — ${label}`} aria-label={`${i.id} ${label}`}
        className={`grid h-9 place-items-center rounded-md border text-xs font-semibold ${item === i.id ? "ring-2 ring-primary" : ""}`}
        style={{ background: bg, color: fg, borderColor: i.state === "available" ? "var(--primary)" : "transparent" }}>
        {cellLabel(i.id)}
      </Link>
    );
  };
  return (
    <>
      <PageHeader crumb={t(lang, "riskMap")} title={tr(lang, "위험 지도 — Security Risks in AI Agents 10분류 × 7항목 + 보강 10", "Risk map — Security Risks in AI Agents 10 × 7 + 10 gaps")} />
      {error && <p className="text-sm text-red-600">{error}</p>}
      <div className="grid grid-cols-[1fr_320px] gap-4">
        <section className="card p-4">
          <div className="space-y-2">
            {rows.map((r) => (
              <div key={r.key} data-2d className="grid min-w-[560px] grid-cols-[110px_repeat(7,1fr)] items-center gap-2">
                <div className="text-xs font-semibold">{LX(lang, r.label)}</div>
                {r.cells.map(cell)}
              </div>
            ))}
            <div data-2d className="grid min-w-[720px] grid-cols-[110px_repeat(10,1fr)] items-center gap-2 pt-2">
              <div className="text-xs font-semibold text-primary">{L(lang, "X 보강")}</div>
              {gaps.map(cell)}
            </div>
          </div>
          <div className="mt-4 flex flex-wrap gap-4 text-xs">
            {Object.entries(STATE).map(([k, [label, bg]]) => (
              <span key={k} className="flex items-center gap-1.5">
                <span className="h-3 w-3 rounded-sm border border-line" style={{ background: bg }} /> {L(lang, label)} ({LX(lang, c[k] ?? 0)})
              </span>
            ))}
          </div>
        </section>
        <aside className="space-y-4">
          <section className="card p-4">
            {sel ? (
              <>
                <div className="text-sm font-bold text-primary">{sel.id} {nm(lang, sel)}</div>
                <div className="text-xs text-muted">{LX(lang, sel.nameEn)} · {LX(lang, sel.priority)} · stage {LX(lang, sel.stage)} · {LX(lang, sel.series)}</div>
                <div className="mt-2 text-xs">{L(lang, "상태: ")}<b>{LX(lang, (STATE[sel.state] ?? STATE.missing)[0])}</b></div>
                {agent ? (
                  <div className="mt-3 space-y-1 text-xs">
                    <div>{L(lang, "에이전트 ")}<b>{agent.id}</b> v{LX(lang, agent.version)} · {LX(lang, agent.gate)} · {LX(lang, agent.isolation)} · fail_{LX(lang, agent.failMode)}</div>
                    <div>{L(lang, "품질: 오탐 ")}{LX(lang, agent.quality?.falsePositiveRate)}{L(lang, " · 탐지 ")}{LX(lang, agent.quality?.detectionRate)} · p95 {LX(lang, agent.quality?.p95Ms)}ms</div>
                    <div className="flex flex-wrap gap-1 pt-1">{standardChips(agent.standards).map((s) => <Chip key={s}>{s}</Chip>)}</div>
                    <div className="flex gap-2 pt-2">
                      <Link href={`/catalog/${agent.id}`} className="btn btn-secondary">{L(lang, "상세 >")}</Link>
                      <Link href={`/findings?agent=${agent.id}`} className="btn btn-secondary">{L(lang, "판정 보기")}</Link>
                    </div>
                  </div>
                ) : <p className="mt-3 text-xs text-muted">{L(lang, "이 항목의 에이전트는 아직 구현되지 않았다 (DP10 누락 보고 대상).")}</p>}
              </>
            ) : <p className="text-sm text-muted">{L(lang, "셀을 누르면 에이전트 요약이 열린다.")}</p>}
          </section>
          <section className="card p-4 text-sm">
            <h2 className="mb-2 font-semibold">{L(lang, "커버리지")}</h2>
            <div className="flex justify-between"><span>{L(lang, "매니페스트")}</span><b>{80 - (c.missing ?? 0)}/80</b></div>
            <div className="flex justify-between"><span>{L(lang, "적용 중")}</span><b>{(c.enforce ?? 0) + (c.partial ?? 0) + (c.observe ?? 0)}/80</b></div>
            <Link href="/instant" className="btn btn-primary mt-3 w-full justify-center">{L(lang, "미적용 항목 켜기 → 즉시 사용")}</Link>
          </section>
        </aside>
      </div>
    </>
  );
}
