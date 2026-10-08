// SCR-D07 배포 토폴로지 — 중앙 게이트웨이·샌드박스 풀·상시 계열 풀·증적 원장·관측 수집기의 위치와 흐름.
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { t, tr, LX } from "@/lib/i18n";
import { prefs } from "@/lib/session";

import { L } from "@/lib/i18n";

const COLOR: Record<string, string> = { ok: "var(--verdict-allow)", degraded: "#9d6105", unknown: "var(--sev-info)", off: "var(--sev-info)", down: "var(--verdict-block)" };

export default async function Topology() {
  const { lang } = await prefs();
  const { data: tp, error } = await safe(api("/v1/topology"), null as any);
  if (!tp) return <><PageHeader crumb={t(lang, "groupGates")} title={tr(lang, "토폴로지", "Topology")} /><Banner tone="danger">{error}</Banner></>;
  const by = Object.fromEntries(tp.nodes.map((n: any) => [n.id, n]));
  const box = (id: string) => { const n = by[id]; return (
    <div key={id} className="card p-3 text-xs" style={{ borderTop: `3px solid ${COLOR[n.status]}` }} data-testid={`node-${id}`}>
      <div className="mb-1 flex items-center justify-between"><b className="text-sm">{LX(lang, n.name)}</b><span style={{ color: COLOR[n.status] }}>{LX(lang, n.status)}</span></div><p>{LX(lang, n.detail)}</p></div>); };
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupGates")} › ${t(lang, "topology")}`} title={tr(lang, `배포 토폴로지 — ${tp.type} ${tp.typeName}`, `Deployment topology — ${tp.type}`)} />
      <div className="mb-3 flex gap-2 text-xs">{Object.entries(tp.alternatives).map(([k, v]) => <Chip key={k}>{k}: {L(lang, String(v))}</Chip>)}</div>
      <div className="grid grid-cols-3 items-start gap-4">
        <div className="space-y-3">{box("console")}<p className="text-center text-xs text-muted">{L(lang, "↓ 서버 액션·API")}</p>{box("gateway")}</div>
        <div className="space-y-3"><p className="text-xs text-muted">{L(lang, "← 요청 단위 격리 발급")}</p>{box("sandbox")}<p className="text-xs text-muted">{L(lang, "← 상시 점검 발견 → 격리 목록 → 관문")}</p>{box("offline")}</div>
        <div className="space-y-3">{box("ledger")}<p className="text-xs text-muted">{L(lang, "↑ 모든 판정·행동·승인 (테넌트별 해시 체인)")}</p>{box("collector")}<p className="text-xs text-muted">{L(lang, "↑ OTLP (수집 단계 마스킹)")}</p></div>
      </div>
      <p className="mt-3 text-xs text-muted">{L(lang, "흐름: ")}{tp.flows.map((f: string[]) => `${f[0]}→${f[1]}`).join(" · ")}</p>
    </>
  );
}
