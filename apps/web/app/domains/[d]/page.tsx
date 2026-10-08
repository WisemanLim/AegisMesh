// SCR-E01~N01 위험 영역 스쿼드 개요 (D1~D10 + X 보강).
import Link from "next/link";
import { notFound } from "next/navigation";
import { Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { standardChips } from "@/lib/format";
import { DETAIL, INSPECTABLE } from "@/lib/domainScreens";
import { DOMAIN_KO, domainName } from "@/lib/riskmap";

import { L, nm, LX, tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";

export default async function Domain({ params }: { params: Promise<{ d: string }> }) {
  const { lang } = await prefs();
  const { d } = await params;
  if (!(d in DOMAIN_KO) && d !== "X") notFound();
  const [items, agents, findings] = await Promise.all([
    safe(api("/v1/risk-items"), { items: [] as any[] }),
    safe(api("/v1/agents"), { items: [] as any[] }),
    safe(api("/v1/findings?limit=500"), { items: [] as any[], total: 0 }),
  ]);
  const mine = items.data.items.filter((i: any) => (d === "X" ? i.kind === "gap" : i.domain === d));
  const byAgent = Object.fromEntries(agents.data.items.map((a: any) => [a.id, a]));
  const counts: Record<string, Record<string, number>> = {};
  for (const f of findings.data.items) {
    const c = (counts[f.agent.id] ??= {});
    const v = f.effectiveVerdict ?? f.verdict;
    c[v] = (c[v] ?? 0) + 1;
  }
  return (
    <>
      <PageHeader crumb={L(lang, "위험 영역")} title={d === "X" ? L(lang, "X 보강 위험 — 도식 공백 10항목") : L(lang, "{0} {1} 스쿼드 개요", d, domainName(lang, d))} />
      {DETAIL[d] && (
        <div className="mb-3 flex flex-wrap gap-2 text-sm" data-testid="detail-links">
          {DETAIL[d].map((x) => (
            <Link key={x.view} href={`/domains/${d.toLowerCase()}/${x.view}`} className="card px-3 py-2 hover:border-primary">
              <span className="text-xs text-muted">{x.scr} · {x.items.join(" · ")}</span><div className="font-semibold text-primary">{tr(lang, x.ko, x.en)} ›</div>
            </Link>
          ))}
          {d === "D1" && <span className="card px-3 py-2 text-xs text-muted">SCR-E02 · {tr(lang, "입력 검사 뷰어 — D1-01·04·05 판정 행의 규칙 링크", "Input inspection viewer — rule links on D1-01·04·05 findings")}</span>}
        </div>
      )}
      <div className="grid grid-cols-2 gap-3">
        {mine.map((i: any) => {
          const a = i.agent ? byAgent[i.agent] : null;
          const c = (i.agent && counts[i.agent]) || {};
          return (
            <section key={i.id} className="card p-4 text-sm">
              <div className="flex items-start justify-between">
                <div><div className="font-semibold">{i.id} {nm(lang, i)}</div><div className="text-xs text-muted">{lang === "en" ? "" : `${i.nameEn} · `} {LX(lang, i.priority)} · stage {LX(lang, i.stage)} · {LX(lang, i.series)}</div></div>
                <Chip tone="primary">{LX(lang, i.state)}</Chip>
              </div>
              {a ? (
                <>
                  <div className="mt-2 text-xs">{L(lang, "에이전트 ")}<Link className="text-primary" href={`/catalog/${a.id}`}>{a.id}</Link> · {LX(lang, a.gate)} · {LX(lang, a.isolation)} · fail_{LX(lang, a.failMode)} · {LX(lang, a.status)}</div>
                  <div className="mt-1 flex flex-wrap gap-1">{standardChips(a.standards).slice(0, 4).map((s) => <Chip key={s}>{s}</Chip>)}</div>
                  <div className="mt-2 flex gap-3 text-xs">
                    {["block", "require_approval", "transform", "alert", "allow"].map((v) => <span key={v}>{v} <b>{LX(lang, c[v] ?? 0)}</b></span>)}
                    <Link className="ml-auto text-primary" href={`/findings?agent=${a.id}`}>{L(lang, "판정 보기 ›")}</Link>
                    {INSPECTABLE.has(a.id) && (() => { const f = findings.data.items.find((x: any) => x.agent.id === a.id && (x.effectiveVerdict ?? x.verdict) !== "allow");
                      return f ? <Link className="text-primary" href={`/domains/d1/inspect/${f.id}`}>{tr(lang, "입력 검사 ›", "Inspect ›")}</Link> : null; })()}
                  </div>
                </>
              ) : <p className="mt-2 text-xs text-muted">{L(lang, "미구현")}</p>}
            </section>
          );
        })}
      </div>
      <p className="mt-3 text-xs text-muted">{L(lang, "판정 수: 최근 500건 기준")}</p>
    </>
  );
}
