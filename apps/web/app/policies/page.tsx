// SCR-D03 정책 목록·버전 — 버전 이력·diff·롤백(2인 승인). 편집·시험·배포는 /policies/edit.
import Link from "next/link";
import { Banner } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { t, tr, LX } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { requestRollback } from "./actions";

import { L } from "@/lib/i18n";

export default async function Policies({ searchParams }: { searchParams: Promise<{ p?: string; from?: string; to?: string; msg?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const sp = await searchParams;
  const { data: list } = await safe(api("/v1/policies"), { tenant: "", items: [] as any[] });
  const pid = sp.p ?? list.items[0]?.id ?? "default";
  const { data: vers } = await safe(api(`/v1/policies/${encodeURIComponent(pid)}/versions`), { items: [] as any[] });
  const from = Number(sp.from ?? vers.items[1]?.version ?? vers.items[0]?.version);
  const to = Number(sp.to ?? vers.items[0]?.version);
  const diff = from && to && from !== to ? (await safe(api(`/v1/policies/${encodeURIComponent(pid)}/diff?from=${from}&to=${to}`), null as any)).data : null;
  const rw = can(user, "policy.write");
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupGates")} › ${t(lang, "policies")}`} title={tr(lang, `정책 목록 · 버전 (pol/${list.tenant})`, `Policies · versions (pol/${list.tenant})`)}
        actions={<><Link className="btn btn-secondary" href="/simulate">{L(lang, "시뮬레이터")}</Link><Link className="btn btn-primary" href={`/policies/edit?p=${pid}`}>{L(lang, "편집기")}</Link></>} />
      {sp.msg && <div className="mb-3"><Banner tone={sp.msg.startsWith(L(lang, "실패")) ? "danger" : "info"}>{L(lang, sp.msg)}</Banner></div>}
      <div className="card mb-4 overflow-hidden">
        <table className="grid-table">
          <thead><tr><th>{L(lang, "정책")}</th><th>{L(lang, "최신")}</th><th>{L(lang, "버전 수")}</th><th>{L(lang, "단위 시험")}</th><th>{L(lang, "재정의")}</th><th>{L(lang, "배포자")}</th><th>{L(lang, "배포 시각")}</th></tr></thead>
          <tbody>{list.items.map((p: any) => (
            <tr key={p.id} className={p.id === pid ? "bg-primary-soft" : ""}>
              <td><Link className="text-primary" href={`/policies?p=${p.id}`}>{p.id}</Link></td><td>v{LX(lang, p.version)}</td><td>{LX(lang, p.versions)}</td>
              <td>{p.tests || <span className="text-muted">0 ⚠</span>}</td><td>{LX(lang, p.overrides)}</td><td>{LX(lang, p.createdBy)}</td><td className="text-xs">{fmtTime(p.createdAt)}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
      <div className="grid grid-cols-[300px_1fr] gap-4">
        <section className="card p-4 text-sm">
          <h2 className="mb-2 font-semibold">{L(lang, "버전 이력 — ")}{pid}</h2>
          <ol className="space-y-1 text-xs">{vers.items.map((v: any) => (
            <li key={v.version} className="flex justify-between gap-2"><span><b>v{LX(lang, v.version)}</b> · {LX(lang, v.createdBy)}</span><span className="text-muted">{fmtTime(v.createdAt)}</span></li>
          ))}</ol>
          {rw && vers.items.length > 1 && (
            <form action={requestRollback} className="mt-4 space-y-2 border-t border-line pt-3">
              <input type="hidden" name="policy" value={pid} />
              <h3 className="font-semibold">{L(lang, "롤백 요청 (2인 승인)")}</h3>
              <select name="target" className="input w-full" aria-label="rollback to">{vers.items.slice(1).map((v: any) => <option key={v.version} value={v.version}>v{LX(lang, v.version)}</option>)}</select>
              <input name="reason" required placeholder={L(lang, "사유(필수)")} className="input w-full" aria-label="rollback reason" />
              <button className="btn btn-danger w-full justify-center">{L(lang, "승인 요청")}</button>
              <p className="text-xs text-muted">{L(lang, "승인 완료 시 선택한 버전 본문으로 새 버전이 배포된다. 이력은 지우지 않는다.")}</p>
            </form>
          )}
        </section>
        <section className="card p-4 text-sm">
          <form method="get" className="mb-2 flex items-center gap-2 text-xs">
            <input type="hidden" name="p" value={pid} />diff
            <select name="from" defaultValue={from} className="input h-7 text-xs" aria-label="from">{vers.items.map((v: any) => <option key={v.version} value={v.version}>v{LX(lang, v.version)}</option>)}</select>→
            <select name="to" defaultValue={to} className="input h-7 text-xs" aria-label="to">{vers.items.map((v: any) => <option key={v.version} value={v.version}>v{LX(lang, v.version)}</option>)}</select>
            <button className="btn btn-secondary h-7 text-xs">{L(lang, "비교")}</button>
          </form>
          <pre tabIndex={0} className="mono max-h-[460px] overflow-auto rounded bg-[#f6f7f9] p-3 text-[11px]" data-testid="policy-diff">
            {diff?.diff || (vers.items.length > 1 ? L(lang, "차이 없음") : vers.items[0]?.yaml ?? "")}
          </pre>
        </section>
      </div>
    </>
  );
}
