// SCR-C10 장터·서드파티 에이전트 — 신뢰 등급·라이선스·심사 상태, 설치 요청(2인 승인 → 등록 심사 R1~R5).
import Link from "next/link";
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { t, tr, nm, LX } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { requestMarketInstall } from "../admin/actions";

import { L } from "@/lib/i18n";

const TIER: Record<string, string> = { official: "공식", partner: "파트너", community: "커뮤니티", external: "외부(출처 미확인)" };
const STATUS: Record<string, string> = { available: "설치 가능", requested: "승인 대기", installed: "설치됨", hold: "보류", rejected: "거부" };

export default async function Marketplace({ searchParams }: { searchParams: Promise<{ msg?: string; tier?: string; status?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const sp = await searchParams;
  const q = new URLSearchParams({ ...(sp.tier ? { tier: sp.tier } : {}), ...(sp.status ? { status: sp.status } : {}) });
  const { data } = await safe(api(`/v1/market?${q}`), { items: [] as any[], tiers: [] as string[] });
  const canReq = can(user, "user.admin");
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupMain")} › ${t(lang, "marketplace")}`} title={tr(lang, "장터 — 서드파티 에이전트", "Marketplace — third-party agents")} />
      {sp.msg && <div className="mb-3"><Banner tone={sp.msg.startsWith(L(lang, "실패")) ? "danger" : "info"}>{L(lang, sp.msg)}</Banner></div>}
      <div className="mb-3 flex flex-wrap gap-2 text-xs">
        {["", ...Object.keys(TIER)].map((k) => <Link key={k || "all"} href={`/marketplace?${new URLSearchParams({ ...(k ? { tier: k } : {}), ...(sp.status ? { status: sp.status } : {}) })}`}
          className={`rounded-full px-3 py-1 ${(sp.tier ?? "") === k ? "bg-primary text-white" : "border border-line bg-panel"}`}>{k ? L(lang, TIER[k]) : L(lang, "전체 등급")}</Link>)}
        <span className="mx-2 text-muted">|</span>
        {["", ...Object.keys(STATUS)].map((k) => <Link key={k || "alls"} href={`/marketplace?${new URLSearchParams({ ...(sp.tier ? { tier: sp.tier } : {}), ...(k ? { status: k } : {}) })}`}
          className={`rounded-full px-3 py-1 ${(sp.status ?? "") === k ? "bg-primary text-white" : "border border-line bg-panel"}`}>{k ? L(lang, STATUS[k]) : L(lang, "전체 상태")}</Link>)}
      </div>
      <div className="grid grid-cols-3 gap-3" data-testid="listings">
        {data.items.length === 0 && <div className="card col-span-3 p-6 text-center text-muted">{L(lang, "장터 목록 없음 — 폐쇄망 번들 반입 또는 서명 번들 제출로 등록된다 (")}<Link className="text-primary" href="/admin/airgap">{L(lang, "반입")}</Link>)</div>}
        {data.items.map((x: any) => {
          const block = x.tier === "external" ? L(lang, "서명 출처 미확인 — 신뢰 게시자 키 등록 후 설치 (MSG-027)") : !canReq ? L(lang, "테넌트·플랫폼 관리자만 요청") : x.status !== "available" && x.status !== "hold" ? L(lang, STATUS[x.status]) : "";
          return (
            <article key={x.id} className="card flex flex-col gap-2 p-4 text-sm">
              <div className="flex items-start justify-between"><div><b>{nm(lang, x)}</b><div className="mono text-xs text-muted">{x.id} · {LX(lang, x.itemId)} · {LX(lang, x.gate)}</div></div>
                <Chip tone={x.tier === "official" || x.tier === "partner" ? "primary" : undefined}>{L(lang, TIER[x.tier])}</Chip></div>
              <div className="flex flex-wrap gap-1 text-xs"><Chip>{L(lang, "라이선스 ")}{LX(lang, x.license)}</Chip><Chip>{L(lang, "격리 ")}{LX(lang, x.isolation)}</Chip><Chip>{x.verdicts.join("/")}</Chip></div>
              <div className="text-xs">{L(lang, "게시자 ")}<span className="mono">{LX(lang, x.publisher ?? "—")}</span> · {LX(lang, x.source)} · {fmtTime(x.createdAt)}</div>
              <div className="text-xs">{L(lang, "상태 ")}<b>{LX(lang, STATUS[x.status] ?? x.status)}</b>{x.reviewRef && <>{L(lang, " · 심사 ")}<Link className="text-primary" href={`/catalog/register?agent=${x.agentId}`}>{LX(lang, x.reviewRef)}</Link></>}</div>
              <form action={requestMarketInstall} className="mt-auto" title={block || undefined}>
                <input type="hidden" name="id" value={x.id} />
                <button className="btn btn-primary w-full justify-center" disabled={!!block}>{L(lang, "설치 요청")}</button>
                {block && <p className="mt-1 text-[11px] text-muted">{block}</p>}
              </form>
            </article>
          );
        })}
      </div>
      <div className="mt-4"><Banner tone="info">{L(lang, "서드파티는 심사 없이 연결할 수 없다 — 설치 요청 → 2인 승인 → 등록 7단계(서명·정적 심사·L1 격리 재생·품질) → 카탈로그. 새 버전은 반입 시 심사 후 무중단 교체.")}</Banner></div>
    </>
  );
}
