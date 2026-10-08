// SCR-A10 설치 검증·커버리지 점검 — 관문 도달·기동 검사·강등 기본값·누락 검증, 언제든 다시 검증.
import Link from "next/link";
import { Banner } from "@/components/Badges";
import { SetupStepper } from "@/components/SetupStepper";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { tr, LX } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { runVerify } from "../actions";

import { L } from "@/lib/i18n";

export default async function SetupVerify({ searchParams }: { searchParams: Promise<{ msg?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const { msg } = await searchParams;
  const [{ data: last }, { data: reach }, { data: pre }] = await Promise.all([
    safe(api("/v1/evidence?kind=setup&limit=1"), { items: [] as any[] }), safe(api("/v1/evidence?kind=setup&limit=8"), { items: [] as any[] }),
    safe(api("/v1/install/precheck"), null as any)]);
  const v = last.items.find((e: any) => e.body.event === "install_verified")?.body;
  const gates = reach.items.filter((e: any) => e.body.event === "gate_reach").slice(0, 3).reverse();
  return (
    <>
      <PageHeader crumb={tr(lang, "첫 실행 5/5", "First run 5/5")} title={tr(lang, "설치 검증 · 커버리지 점검", "Install verification · coverage")} />
      <SetupStepper current={5} />
      {msg && <div className="mb-3"><Banner tone={msg.includes(L(lang, "실패")) || msg.includes(L(lang, "주의")) ? "warn" : "info"}>{L(lang, msg)}</Banner></div>}
      <div className="grid grid-cols-2 gap-4" data-testid="verify">
        <section className="card p-4 text-sm"><h2 className="mb-2 font-semibold">{L(lang, "관문 도달 시험 ")}{v ? `(${fmtTime(last.items[0].createdAt)} · ${v.by})` : ""}</h2>
          {gates.length === 0 ? <p className="text-xs text-muted">{L(lang, "아직 검증 전 — 다시 검증")}</p> : <ul className="space-y-1 text-xs">{gates.map((g: any) => (
            <li key={g.seq}>{LX(lang, g.body.gate)}: {LX(lang, g.body.agent)} → {LX(lang, g.body.verdict)} · {LX(lang, g.body.latencyMs)}{L(lang, "ms · 증적 seq ")}{g.seq} ✓</li>))}</ul>}
          {v && <ul className="mt-2 space-y-1 text-xs">{Object.entries(v.startup).map(([k, ok]) => <li key={k} style={{ color: ok ? "var(--verdict-allow)" : "var(--verdict-block)" }}>{ok ? "✓" : "✗"} {L(lang, ({ isolation: "격리 등급 기동 검사", signature: "서드파티 서명·심사", failmode: "강등 기본값 C1·C2 closed / C3·C4 open", coverage: "도식 80항목 누락 검증" } as any)[k])}</li>)}</ul>}
          {can(user, "tenant.admin") && <form action={runVerify} className="mt-3"><button className="btn btn-primary h-8 text-xs">{L(lang, "다시 검증")}</button></form>}</section>
        <section className="card p-4 text-sm"><h2 className="mb-2 font-semibold">{L(lang, "사전 점검 ")}{pre ? `${pre.passed}/${pre.total}` : ""}</h2>
          <ul className="space-y-1 text-xs">{pre?.checks.map((c: any) => <li key={c.id} style={{ color: c.ok ? undefined : c.level === "required" ? "var(--verdict-block)" : "#9d6105" }}>{c.ok ? "✓" : "⚠"} {LX(lang, c.title)} — {LX(lang, c.detail)}</li>)}</ul>
          <p className="mt-2 text-xs"><Link className="text-primary" href="/coverage">{L(lang, "커버리지 상세")}</Link> · <Link className="text-primary" href="/install">{L(lang, "설치 안내")}</Link></p></section>
      </div>
      <div className="mt-4 flex justify-between"><Link className="btn btn-secondary" href="/setup/first-verdict">{L(lang, "← 이전")}</Link><Link className="btn btn-primary" href="/overview">{L(lang, "완료 → 개요")}</Link></div>
    </>
  );
}
