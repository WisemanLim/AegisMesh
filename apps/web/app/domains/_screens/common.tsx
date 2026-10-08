// 도메인 상세 화면 공통 블록 (서버 컴포넌트) — 머리글·에이전트 띠·최근 판정·설정 카드.
import Link from "next/link";
import { AgentSettings } from "@/components/AgentSettings";
import { Banner, Chip, VerdictBadge } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { DETAIL, type DetailScreen, findingHref } from "@/lib/domainScreens";
import { fmtTime, shortHash } from "@/lib/format";
import { type Lang, nm, tr } from "@/lib/i18n";
import { domainName } from "@/lib/riskmap";
import { type Me, can } from "@/lib/session";

export type ScreenProps = { lang: Lang; user: Me | null; d: string; screen: DetailScreen; sp: Record<string, string | undefined> };

export function DetailHeader({ lang, d, screen, msg }: { lang: Lang; d: string; screen: DetailScreen; msg?: string }) {
  const D = d.toUpperCase();
  return (
    <>
      <PageHeader crumb={`${tr(lang, "위험 영역", "Risk domains")} › ${D} ${domainName(lang, D)} › ${tr(lang, screen.ko, screen.en)}`} title={tr(lang, screen.ko, screen.en)} />
      <div className="mb-3 flex flex-wrap items-center gap-2 text-xs">
        <Chip tone="primary">{screen.scr}</Chip>{screen.items.map((i) => <Chip key={i}>{i}</Chip>)}
        <span className="ml-auto flex gap-3">
          <Link className="text-primary" href={`/domains/${D}`}>{tr(lang, "← 스쿼드 개요", "← Squad overview")}</Link>
          {DETAIL[D].filter((x) => x.view !== screen.view).map((x) => <Link key={x.view} className="text-primary" href={`/domains/${d.toLowerCase()}/${x.view}`}>{tr(lang, x.ko, x.en)} ›</Link>)}
        </span>
      </div>
      {msg && <div className="mb-3"><Banner tone={/^(실패|Failed)/.test(msg) ? "danger" : "info"}>{msg}</Banner></div>}
    </>
  );
}

export async function AgentStrip({ lang, ids }: { lang: Lang; ids: string[] }) {
  const rows = await Promise.all(ids.map((i) => safe(api(`/v1/agents/${i}`), null as any)));
  return (
    <div className="mb-3 flex flex-wrap gap-2 text-xs">
      {rows.map(({ data: a }, i) => a ? (
        <Link key={a.id} href={`/catalog/${a.id}`} className="card flex items-center gap-2 px-3 py-1.5">
          <b>{a.id}</b> {nm(lang, a)} · {a.series} · {a.gate} · fail_{a.failMode} · <span style={{ color: a.status === "active" ? "var(--verdict-allow)" : "#9d6105" }}>{a.status}</span>
          {a.quality && <span className="text-muted">· {tr(lang, "탐지", "det")} {a.quality.detectionRate} · {tr(lang, "오탐", "FP")} {a.quality.falsePositiveRate}</span>}
        </Link>
      ) : <span key={ids[i]} className="text-muted">{ids[i]} —</span>)}
    </div>
  );
}

export async function Recent({ lang, ids, limit = 15, title }: { lang: Lang; ids: string[]; limit?: number; title?: string }) {
  const res = await Promise.all(ids.map((i) => safe(api(`/v1/findings?agent=${i}&limit=${limit}`), { items: [] as any[], total: 0 })));
  const items = res.flatMap((r) => r.data.items).sort((a: any, b: any) => String(b.occurredAt).localeCompare(String(a.occurredAt))).slice(0, limit);
  return (
    <section className="card overflow-hidden text-sm" data-testid="recent">
      <h2 className="p-3 font-semibold">{title ?? tr(lang, "최근 판정", "Recent findings")} <span className="text-xs font-normal text-muted">({res.reduce((n, r) => n + (r.data.total ?? 0), 0)})</span></h2>
      <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "시각", "Time")}</th><th>{tr(lang, "에이전트", "Agent")}</th><th>{tr(lang, "유효 판정", "Effective")}</th><th>{tr(lang, "규칙", "Rule")}</th><th>{tr(lang, "주체", "Principal")}</th><th>trace</th></tr></thead>
        <tbody>{items.length === 0 ? <tr><td colSpan={6} className="text-muted">{tr(lang, "판정 없음", "No findings")}</td></tr> : items.map((f: any) => (
          <tr key={f.id}><td>{fmtTime(f.occurredAt)}</td><td>{f.agent.id}</td><td><VerdictBadge v={f.effectiveVerdict ?? f.verdict} /></td>
            <td className="mono"><Link className="text-primary" href={findingHref(f)}>{f.ruleId}</Link></td>
            <td>{f.subject?.principal?.id ?? "—"}</td><td className="mono"><Link className="text-primary" href={`/findings?trace=${f.traceId}`}>{shortHash(f.traceId)}</Link></td></tr>
        ))}</tbody></table>
    </section>
  );
}

export async function SettingsCard({ lang, user, id, title, showRules = false, sample, principal }: { lang: Lang; user: Me | null; id: string; title?: string; showRules?: boolean; sample?: object; principal?: string }) {
  const { data: cfg } = await safe(api(`/v1/agents/${id}/config${principal ? `?principal=${encodeURIComponent(principal)}` : ""}`), null as any);
  if (!cfg) return null;
  return (
    <section className="card p-4 text-sm" data-testid={`settings-${id}`}>
      <h2 className="mb-2 font-semibold">{title ?? tr(lang, `${id} 설정`, `${id} settings`)}</h2>
      <AgentSettings key={principal ?? "*"} cfg={cfg} editable={can(user, "policy.write")} showRules={showRules && !principal} sample={sample} />
    </section>
  );
}
