// SCR-O04 사건 상세·연쇄 그래프 + SCR-O07 대응 런북.
import Link from "next/link";
import { notFound } from "next/navigation";
import { Banner, Chip, SeverityBadge, VerdictBadge } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { incidentAction } from "@/lib/actions";
import { ApiError, api } from "@/lib/api";
import { fmtTime, shortHash } from "@/lib/format";
import { can, me, prefs } from "@/lib/session";

import { L, type Lang, LX } from "@/lib/i18n";

function Graph({ nodes, edges, lang }: { nodes: string[]; edges: [string, string][]; lang: Lang }) {
  const w = 560, h = 120, step = nodes.length > 1 ? (w - 80) / (nodes.length - 1) : 0;
  const pos = Object.fromEntries(nodes.map((n, i) => [n, { x: 40 + i * step, y: h / 2 }]));
  const uniq = Array.from(new Set(edges.map((e) => e.join(">")))).map((k) => k.split(">"));
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full" role="img" aria-label={L(lang, "연쇄 그래프")}>
      {uniq.map(([a, b], i) => {
        const p = pos[a], q = pos[b];
        if (!p || !q) return null;
        const mid = (p.x + q.x) / 2, bend = p.x < q.x ? -30 : 30;
        return <path key={i} d={`M${p.x},${p.y} Q${mid},${p.y + bend} ${q.x},${q.y}`} fill="none" stroke="var(--primary)" strokeWidth="1.5" markerEnd="url(#arr)" />;
      })}
      <defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="var(--primary)" /></marker></defs>
      {nodes.map((n) => (
        <g key={n}>
          <circle cx={pos[n].x} cy={pos[n].y} r="26" fill="var(--primary-soft)" stroke="var(--primary)" />
          <text x={pos[n].x} y={pos[n].y + 4} textAnchor="middle" fontSize="10" fill="var(--ink)">{n}</text>
        </g>
      ))}
    </svg>
  );
}

export default async function IncidentDetail({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<{ msg?: string }> }) {
  const { lang } = await prefs();
  const { id } = await params;
  const { msg } = await searchParams;
  const user = await me();
  let i: any;
  try {
    i = await api(`/v1/incidents/${id}`);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound();
    throw e;
  }
  const ro = !can(user, "incident");
  return (
    <>
      <PageHeader crumb={L(lang, "사건 › 상세")} title={LX(lang, i.title)} />
      {msg && <div className="mb-3"><Banner tone={msg.startsWith(L(lang, "실패")) ? "danger" : "info"}>{L(lang, msg)}</Banner></div>}
      <div className="grid grid-cols-3 gap-4">
        <section className="card col-span-2 p-4 text-sm">
          <div className="mb-3 flex items-center gap-2"><SeverityBadge s={i.severity} /><Chip>{LX(lang, i.domain)}</Chip><Chip tone="primary">{LX(lang, i.status)}</Chip>{i.contained && <Chip>{L(lang, "봉쇄됨")}</Chip>}</div>
          <h2 className="mb-1 font-semibold">{L(lang, "연쇄 그래프 (판정 순서)")}</h2>
          <Graph lang={lang} nodes={i.graph.nodes} edges={i.graph.edges} />
          <h2 className="mb-2 mt-4 font-semibold">{L(lang, "타임라인")}</h2>
          <table className="grid-table"><thead><tr><th>{L(lang, "시각")}</th><th>{L(lang, "관문")}</th><th>{L(lang, "에이전트")}</th><th>{L(lang, "규칙")}</th><th>{L(lang, "유효 판정")}</th><th>trace</th></tr></thead><tbody>
            {i.timeline.map((x: any) => (
              <tr key={x.findingId}><td className="text-xs">{fmtTime(x.at)}</td><td>{LX(lang, x.gate)}</td><td>{LX(lang, x.agent)}</td>
                <td className="mono"><Link className="text-primary" href={`/findings/${x.findingId}`}>{LX(lang, x.ruleId)}</Link></td>
                <td><VerdictBadge v={x.verdict} /></td><td className="mono text-xs">{shortHash(x.traceId)}</td></tr>
            ))}
          </tbody></table>
        </section>
        <aside className="space-y-4">
          <section className="card p-4 text-sm">
            <h2 className="mb-2 font-semibold">{L(lang, "대응")}</h2>
            {(["contain", "close"] as const).map((act) => (
              <form key={act} action={incidentAction} className="mb-2 flex gap-2">
                <input type="hidden" name="id" value={i.id} /><input type="hidden" name="act" value={act} />
                <input name="note" placeholder={L(lang, "메모")} className="input flex-1" aria-label={`${act} note`} />
                <button className={`btn ${act === "close" ? "btn-danger" : "btn-primary"}`} disabled={ro || i.status === "closed" || (act === "contain" && i.contained)}>
                  {act === "contain" ? L(lang, "봉쇄") : L(lang, "종결")}
                </button>
              </form>
            ))}
            <p className="text-xs text-muted">{L(lang, "봉쇄 전에는 종결할 수 없다. 모든 조치는 원장에 남는다.")}</p>
          </section>
          <section className="card p-4 text-sm">
            <h2 className="mb-2 font-semibold">{L(lang, "런북 ")}{LX(lang, i.runbook ?? "—")}</h2>
            <pre className="whitespace-pre-wrap text-xs leading-5">{(lang === "en" && i.runbookTextEn) || LX(lang, i.runbookText ?? L(lang, "이 도메인의 런북이 없다 (X08 점검 대상)."))}</pre>
            <Link className="btn btn-primary mt-2 h-8 text-xs" href={`/incidents/${i.id}/response`} data-testid="runbook-run">{lang === "en" ? "Run the runbook · forensic replay ›" : "런북 실행 · 포렌식 재현 ›"}</Link>
          </section>
        </aside>
      </div>
    </>
  );
}
