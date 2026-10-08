// SCR-O05 사람 승인 대기함 + SCR-O06 승인 결정(2인 승인) — 본인 요청 승인 불가, 사유 필수.
import Link from "next/link";
import { Banner, Chip, VerdictBadge } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime, shortHash } from "@/lib/format";
import { t, tr, LX } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { approve, decide, reject } from "./actions";

import { L } from "@/lib/i18n";

export default async function Approvals({ searchParams }: { searchParams: Promise<{ msg?: string; status?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const principal = user?.username ?? "";
  const { msg, status = "pending" } = await searchParams;
  const { data, error } = await safe(api(`/v1/approvals?status=${status}`), { items: [] as any[] });
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupOps")} › ${t(lang, "approvals")}`} title={tr(lang, "사람 승인 대기함", "Human approval inbox")} />
      <div className="mb-3 flex gap-2 text-sm">
        {["pending", "approved", "rejected"].map((s) => (
          <Link key={s} href={`/approvals?status=${s}`} className={`rounded-full px-3 py-1 ${s === status ? "bg-primary text-white" : "bg-panel border border-line"}`}>{s}</Link>
        ))}
        <span className="ml-auto text-xs text-muted">{L(lang, "현재 주체: ")}<b>{principal}</b>{can(user, "approve") ? "" : L(lang, " (승인자 역할 없음)")}</span>
      </div>
      {msg && <div className="mb-3"><Banner tone={msg.startsWith(L(lang, "실패")) ? "danger" : "info"}>{L(lang, msg)}</Banner></div>}
      {error && <p className="text-sm text-red-600">{error}</p>}
      <div className="space-y-3">
        {data.items.length === 0 && <div className="card p-6 text-center text-muted">{t(lang, "noData")}</div>}
        {data.items.map((a: any) => {
          const own = a.requestedBy === principal;
          const already = a.decisions.some((d: any) => d.principal === principal);
          const blockReason = !can(user, "approve") ? t(lang, "readOnly") : own ? L(lang, "본인이 요청한 행동은 승인할 수 없다 (MSG-011)") : already ? L(lang, "이미 결정함 (2인 승인)") : "";
          return (
            <article key={a.id} className="card flex gap-4 p-4" style={{ borderLeft: "4px solid var(--verdict-approval)" }}>
              <div className="flex-1 text-sm">
                <div className="font-semibold">{LX(lang, a.summary)} <Link className="text-xs font-normal text-primary" href={`/approvals/${a.id}`} data-testid="approval-detail">{tr(lang, "상세 ›", "Details ›")}</Link></div>
                <div className="mt-1 text-xs text-muted">
                  {a.id}{L(lang, " · 요청 ")}{LX(lang, a.requestedBy)} · {LX(lang, a.gate)}{L(lang, " 관문 · ")}{fmtTime(a.createdAt)} · trace <Link className="mono" href={`/findings?trace=${a.traceId}`}>{shortHash(a.traceId)}</Link>
                </div>
                <div className="mt-2 flex flex-wrap gap-1">{a.findingIds.map((f: string) => <Link key={f} href={`/findings/${f}`}><Chip>{f}</Chip></Link>)}</div>
                {a.decisions.length > 0 && (
                  <ul className="mt-2 text-xs">{a.decisions.map((d: any) => <li key={d.principal}>{LX(lang, d.principal)}: {LX(lang, d.decision)} — {LX(lang, d.reason)} ({fmtTime(d.at)})</li>)}</ul>
                )}
              </div>
              <div className="w-80 text-sm">
                <div className="flex items-center justify-between"><VerdictBadge v="require_approval" /><span className="font-semibold">{LX(lang, a.status)} · {a.decisions.filter((d: any) => d.decision === "approve").length}/{LX(lang, a.required)}</span></div>
                {a.status === "pending" && (
                  <form action={decide} className="mt-2 space-y-2">
                    <input type="hidden" name="id" value={a.id} />
                    <input name="reason" required placeholder={t(lang, "reason")} className="input w-full" aria-label="reason" disabled={!!blockReason} />
                    <div className="flex gap-2" title={blockReason || undefined}>
                      <button formAction={approve} className="btn btn-primary" disabled={!!blockReason}>{t(lang, "approve")}</button>
                      <button formAction={reject} className="btn btn-danger" disabled={!!blockReason}>{t(lang, "reject")}</button>
                    </div>
                    {blockReason && <p className="text-xs text-muted">{blockReason}</p>}
                  </form>
                )}
              </div>
            </article>
          );
        })}
      </div>
      <div className="mt-4"><Banner tone="info">{L(lang, "본인 요청 승인 불가 · 사유 필수 · 되돌릴 수 없는 행동은 2인 승인 (MSG-010·011)")}</Banner></div>
    </>
  );
}
