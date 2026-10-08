// 상시 점검(C3) 대상·격리 목록 — PRD §8.2 "발견 → 인라인 정책 동적 변경".
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { addScanTarget, releaseQuarantine, runScanTarget } from "@/lib/actions";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { t, tr, LX } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";

import { L } from "@/lib/i18n";

export default async function Scan({ searchParams }: { searchParams: Promise<{ msg?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const { msg } = await searchParams;
  const [targets, q] = await Promise.all([safe(api("/v1/scan-targets"), { items: [] as any[] }), safe(api("/v1/quarantine"), { items: [] as any[] })]);
  const ro = !can(user, "scan");
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupOpsRt")} › ${t(lang, "scan")}`} title={tr(lang, "상시 점검 대상 · 격리 목록", "Continuous scan targets · quarantine")} />
      {msg && <div className="mb-3"><Banner tone={msg.startsWith(L(lang, "실패")) ? "danger" : "info"}>{L(lang, msg)}</Banner></div>}
      <h2 className="mb-2 font-semibold">{L(lang, "격리 목록 (관문이 즉시 참조)")}</h2>
      <div className="card mb-5 overflow-hidden">
        <table className="grid-table">
          <thead><tr><th>ID</th><th>{L(lang, "종류")}</th><th>{L(lang, "대상")}</th><th>{L(lang, "사유")}</th><th>{L(lang, "시각")}</th><th /></tr></thead>
          <tbody>
            {q.data.items.length === 0 && <tr><td colSpan={6} className="text-muted">{t(lang, "noData")}</td></tr>}
            {q.data.items.map((x: any) => (
              <tr key={x.id}><td className="mono">{x.id}</td><td><Chip>{LX(lang, x.kind)}</Chip></td><td className="font-semibold">{LX(lang, x.value)}</td><td className="text-xs">{LX(lang, x.reason)}</td><td className="text-xs">{fmtTime(x.createdAt)}{x.expiresAt && <div className="text-muted">{L(lang, "기한 {0}", fmtTime(x.expiresAt))}</div>}</td>
                <td><form action={releaseQuarantine}><input type="hidden" name="id" value={x.id} /><button className="btn btn-danger" disabled={ro}>{["principal", "session"].includes(x.kind) ? L(lang, "해제 요청(2인)") : L(lang, "해제")}</button></form></td></tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="grid grid-cols-[1fr_360px] gap-4">
        <div className="card overflow-hidden">
          <table className="grid-table">
            <thead><tr><th>{L(lang, "대상")}</th><th>{L(lang, "종류")}</th><th>{L(lang, "주기")}</th><th>{L(lang, "마지막")}</th><th>{L(lang, "결과")}</th><th /></tr></thead>
            <tbody>
              {targets.data.items.length === 0 && <tr><td colSpan={6} className="text-muted">{t(lang, "noData")}</td></tr>}
              {targets.data.items.map((x: any) => (
                <tr key={x.id}><td>{LX(lang, x.name)}<div className="mono text-xs text-muted">{x.id}</div></td><td><Chip>{LX(lang, x.kind)}</Chip></td><td>{LX(lang, x.intervalSec)}s</td>
                  <td className="text-xs">{fmtTime(x.lastRunAt)}</td><td>{LX(lang, x.lastVerdict ?? "—")}</td>
                  <td><form action={runScanTarget}><input type="hidden" name="id" value={x.id} /><button className="btn btn-secondary" disabled={ro}>{L(lang, "지금 점검")}</button></form></td></tr>
              ))}
            </tbody>
          </table>
        </div>
        <form action={addScanTarget} className="card space-y-2 p-4 text-sm">
          <h2 className="font-semibold">{L(lang, "점검 대상 등록")}</h2>
          <input name="name" required placeholder={L(lang, "이름 (예 kb-search)")} className="input w-full" aria-label="name" />
          <input name="interval" type="number" min="10" defaultValue={3600} className="input w-full" aria-label="interval" />
          <textarea name="artifact" required rows={6} className="mono w-full rounded-md border border-line p-2" aria-label="artifact"
            defaultValue={'{"kind":"mcp_server","name":"kb-search","signed":true,"signatureValid":true,"registryApproved":true,"version":"1.4.2","tools":[]}'} />
          <button className="btn btn-primary" disabled={ro}>{L(lang, "등록")}</button>
        </form>
      </div>
    </>
  );
}
