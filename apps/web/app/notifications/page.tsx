// SCR-B06 알림 센터 — 강등·오탐 예산·품질 회귀·지연 예산·서명 실패·업데이트·승인·사건을 시간순으로, 각 화면으로 이동.
import Link from "next/link";
import { Banner } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { t, tr, LX } from "@/lib/i18n";
import { prefs } from "@/lib/session";

const SEV: Record<string, string> = { critical: "#8b0000", high: "var(--verdict-block)", medium: "#9d6105", low: "#3b6fd8", info: "var(--sev-info)" };

export default async function Notifications({ searchParams }: { searchParams: Promise<{ sev?: string }> }) {
  const { lang } = await prefs();
  const { sev } = await searchParams;
  const { data, error } = await safe(api("/v1/notifications"), { items: [] as any[], counts: {} as Record<string, number> });
  const items = sev ? data.items.filter((i: any) => i.severity === sev) : data.items;
  return (
    <>
      <PageHeader crumb={t(lang, "notifications")} title={tr(lang, "알림 센터 (72시간)", "Notification center (72h)")} />
      {error && <Banner tone="danger">{error}</Banner>}
      <div className="mb-3 flex gap-2 text-xs">
        <Link href="/notifications" className={`rounded-full px-3 py-1 ${!sev ? "bg-primary text-white" : "border border-line bg-panel"}`}>{tr(lang, "전체", "All")} {data.items.length}</Link>
        {Object.entries(data.counts as Record<string, number>).map(([k, n]) => (
          <Link key={k} href={`/notifications?sev=${k}`} className={`rounded-full px-3 py-1 ${sev === k ? "bg-primary text-white" : "border border-line bg-panel"}`}>{k} {n}</Link>
        ))}
      </div>
      <ul className="card divide-y divide-line" data-testid="notifications">
        {items.length === 0 && <li className="p-6 text-center text-muted">{t(lang, "noData")}</li>}
        {items.map((n: any, i: number) => (
          <li key={i} className="flex items-center gap-3 px-4 py-2.5 text-sm">
            <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: SEV[n.severity] }} title={n.severity} />
            <span className="w-24 shrink-0 text-xs font-semibold">{LX(lang, n.kind)}</span>
            <Link href={n.href} className="flex-1 hover:text-primary">{LX(lang, n.text)}</Link>
            <span className="text-xs text-muted">{fmtTime(n.at)}</span>
          </li>
        ))}
      </ul>
    </>
  );
}
