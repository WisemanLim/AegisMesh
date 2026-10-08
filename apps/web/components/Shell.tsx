// SCR-B01 콘솔 셸 — 좌측 메뉴 220px · 상단 바 48px · 하단 상태 줄 24px.
import Link from "next/link";
import { t, tr, type Lang, LX } from "@/lib/i18n";
import { domainName } from "@/lib/riskmap";
import type { Me } from "@/lib/session";
import { CommandPalette } from "@/components/CommandPalette";
import { Tray } from "@/components/Tray";

import { L } from "@/lib/i18n";

type NavGroup = "groupMain" | "groupGates" | "groupOps" | "groupGov" | "groupDomains" | "groupOpsRt" | "groupExtended" | "groupAdmin";
type NavItem = { href: string; key?: Parameters<typeof t>[1]; label?: string; perm?: string };
const NAV: { group: NavGroup; items: NavItem[] }[] = [
  { group: "groupMain", items: [{ href: "/overview", key: "overview" }, { href: "/success", key: "success" }, { href: "/risk-map", key: "riskMap" }, { href: "/catalog", key: "catalog" },
    { href: "/catalog/register", key: "register" }, { href: "/instant", key: "instant" }, { href: "/instant/profiles", key: "instantWizard" }, { href: "/instant/preview", key: "preview" }, { href: "/profiles/edit", key: "profileEditor" }, { href: "/marketplace", key: "marketplace" }] },
  { group: "groupGates", items: [{ href: "/gates", key: "gates" }, { href: "/policies", key: "policies" }, { href: "/policies/edit", key: "policyEditor" },
    { href: "/simulate", key: "simulate" }, { href: "/topology", key: "topology" }] },
  { group: "groupDomains", items: ["D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "D10", "X"].map((d) => ({ href: `/domains/${d}`, label: d })) },
  { group: "groupOps", items: [{ href: "/findings", key: "findings" }, { href: "/incidents", key: "incidents" }, { href: "/approvals", key: "approvals" }] },
  { group: "groupGov", items: [{ href: "/evidence", key: "evidence" }, { href: "/reports", key: "reports" }, { href: "/risks", key: "risks" },
    { href: "/governance", key: "governance" }, { href: "/coverage", key: "coverage" }, { href: "/compliance/fairness", key: "fairness" }, { href: "/compliance/cards", key: "cards" }] },
  { group: "groupOpsRt", items: [{ href: "/scan", key: "scan" }, { href: "/redteam", key: "redteam" }, { href: "/redteam/run", key: "redteamRun" },
    { href: "/redteam/baseline", key: "baseline" }, { href: "/observability", key: "observability" }, { href: "/observability/slo", key: "slo" }] },
  { group: "groupExtended", items: [["x01", "X01 에이전트 간 통신"], ["x04", "X04 이탈 에이전트"], ["x05", "X05 출력 무해화"], ["x06", "X06 멀티모달"],
    ["x07", "X07 모델·추론 계층"]].map(([id, label]) => ({ href: `/extended/${id}`, label })) },
  { group: "groupAdmin", items: [{ href: "/admin/tenants", key: "tenants", perm: "read" }, { href: "/admin/users", key: "users", perm: "user.admin" }, { href: "/admin/sso", key: "sso", perm: "tenant.admin" }, { href: "/admin/identity", key: "identity", perm: "read" }, { href: "/admin/sandbox", key: "sandbox", perm: "read" }, { href: "/admin/updates", key: "updates", perm: "read" }, { href: "/admin/airgap", key: "airgap", perm: "read" }, { href: "/admin/data-protection", key: "dataProtection", perm: "read" }, { href: "/install", key: "install", perm: "read" },
    { href: "/account", key: "account" }] },
];

export type ShellStatus = {
  mode: string; profile: string | null; policy: string | null; chainOk: boolean | null; degraded: number;
  activeAgents: number; pending: number; gates: Record<string, { status: string; p95: number; budget: number | null; degraded?: string[]; mode?: string | null }>;
  alerts: number; degradedGates: { gate: string; agents: string[]; mode: string }[];
};

// CMP-15 관문 칩 — 강등 중이면 closed 적색 · open 주황 (전 화면 공통). 클릭 → 관문 상세(SCR-D02)
const GATE_COLOR: Record<string, string> = { ok: "var(--verdict-allow)", near: "#e2b007", over: "var(--verdict-block)", none: "var(--sev-info)",
  "degraded-closed": "var(--verdict-block)", "degraded-open": "var(--verdict-approval)" };

export function Shell({ lang, me, status, children }: { lang: Lang; me: Me; status: ShellStatus; children: React.ReactNode }) {
  // 1024px 이상 = 화면설계서 셸(좌측 메뉴 220px) 그대로 · 좁은 화면(확대 400% = 320 CSS px 포함)은 메뉴를 접고 한 줄로 흐른다 (WCAG 1.4.10, Epic 45)
  const nav = NAV.map((g) => (
    <div key={g.group} className="mb-3">
      <div className="px-4 pb-1 text-[11px] font-semibold uppercase tracking-wide text-muted">{t(lang, g.group)}</div>
      {g.items.filter((i) => !i.perm || me.permissions.includes(i.perm)).map((i) => (
        <Link key={i.href} href={i.href} className="block px-4 py-1.5 text-sm hover:bg-primary-soft hover:text-primary">
          {i.key ? t(lang, i.key) : i.label === "X" ? L(lang, "X 보강") : i.href.startsWith("/extended/") ? L(lang, i.label ?? "") : `${i.label} ${domainName(lang, i.label ?? "")}`}
        </Link>
      ))}
    </div>
  ));
  return (
    <div className="flex min-h-screen flex-col">
      <a href="#main" className="skip-link">{tr(lang, "본문 바로가기", "Skip to main content")}</a>
      <header className="flex min-h-12 flex-wrap items-center gap-x-4 gap-y-1 border-b border-line bg-panel px-4 py-1">
        <Link href="/overview" className="flex items-center gap-2 font-bold text-navy lg:w-[196px]">
          <span aria-hidden className="grid h-7 w-7 place-items-center rounded-full bg-navy text-xs text-white">◆</span> AegisMesh
        </Link>
        <span className="rounded-md bg-primary-soft px-2 py-1 text-xs font-semibold text-primary" title={L(lang, "테넌트 범위")}>{me.scope === "*" ? t(lang, "allTenants") : me.scope} · {LX(lang, status.mode)}</span>
        <nav aria-label="gates" className="flex flex-wrap gap-2">
          {["input", "tool", "output", "evidence"].map((g) => {
            const s = status.gates[g];
            const st = g === "evidence" ? (status.chainOk === false ? "over" : "ok") : s?.status ?? "none";
            const deg = st.startsWith("degraded-");
            return (
              <Link key={g} href={g === "evidence" ? "/evidence" : `/gates/${g}`} data-testid={`chip-${g}`} data-status={st}
                className="flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs" style={{ borderColor: deg ? GATE_COLOR[st] : undefined, color: deg ? GATE_COLOR[st] : undefined }}
                title={s ? `p95 ${s.p95.toFixed(2)}ms / ${s.budget ?? "-"}ms${deg ? ` · degraded ${s.degraded?.join(", ")} (fail-${s.mode})` : ""}` : L(lang, "관측 없음")}>
                <span className="h-2 w-2 rounded-full" style={{ background: GATE_COLOR[st] }} />
                {g}{s && s.status !== "none" ? ` ${s.p95.toFixed(1)}ms` : ""}{deg ? ` ⛔ ${s?.mode}` : ""}
              </Link>
            );
          })}
        </nav>
        <CommandPalette perms={me.permissions} />
        <div className="ml-auto flex flex-wrap items-center gap-3 text-sm">
          <Link href="/notifications" className="font-semibold" title={t(lang, "notifications")} data-testid="bell">🔔 {LX(lang, status.alerts)}</Link>
          <Tray lang={lang} pending={status.pending} canApprove={me.permissions.includes("approve")} label={t(lang, "approvalsPending")} />
          <form action="/prefs" method="post" className="flex items-center gap-2">
            {me.tenant === null ? (
              <select name="tenant" defaultValue={me.scope} className="input h-7 max-w-48 text-xs" aria-label="tenant">
                <option value="*">{t(lang, "allTenants")}</option>
                {me.tenants.map((x) => <option key={x.id} value={x.id}>{x.id} · {LX(lang, x.name)}</option>)}
              </select>
            ) : null}
            <select name="lang" defaultValue={lang} className="input h-7 text-xs" aria-label="language">
              <option value="ko">ko</option>
              <option value="en">en</option>
            </select>
            <button className="btn btn-secondary h-7 text-xs">OK</button>
          </form>
          <Link href="/account" className="flex items-center gap-1.5 rounded-full border border-line px-2.5 py-0.5 text-xs" title={me.roles.map((r) => me.roleNames[r] ?? r).join(", ")}>
            <span className="grid h-5 w-5 place-items-center rounded-full bg-navy text-[10px] text-white">{LX(lang, me.displayName).slice(0, 1)}</span>
            {LX(lang, me.displayName)}{me.breakGlass ? " ⚠" : ""}
          </Link>
          <form action="/logout" method="post"><button className="btn btn-secondary h-7 text-xs">{t(lang, "logout")}</button></form>
        </div>
      </header>
      <div className="flex flex-1 flex-col lg:flex-row">
        <details className="border-b border-line bg-panel lg:hidden" data-testid="nav-compact">
          <summary className="cursor-pointer px-4 py-2 text-sm font-semibold">{tr(lang, "메뉴", "Menu")}</summary>
          <nav aria-label={tr(lang, "주 메뉴", "Main menu")} className="py-2">{nav}</nav>
        </details>
        <aside className="hidden w-[220px] shrink-0 border-r border-line bg-panel py-3 lg:block">
          <nav aria-label={tr(lang, "주 메뉴", "Main menu")}>{nav}</nav>
        </aside>
        <main id="main" tabIndex={-1} className="mx-auto w-full min-w-0 max-w-[1600px] flex-1 p-4 focus:outline-none sm:p-6">
          {status.degradedGates.length > 0 && (
            <Link href="/gates/degradation" role="alert" data-testid="shell-degraded" className="mb-3 block rounded-lg px-4 py-2 text-sm" style={{ background: "#fdecec", color: "#c03333", border: "1px solid #c0333333" }}>
              ⛔ {status.degradedGates.map((d) => tr(lang, `${d.gate} 관문 강등 — ${d.agents.join(", ")} → fail-${d.mode}${d.mode === "closed" ? " 응답 차단 중" : " 통과 + 경보"}`,
                `${d.gate} gate degraded — ${d.agents.join(", ")} → fail-${d.mode}${d.mode === "closed" ? ", blocking responses" : ", pass + alert"}`)).join(" · ")}
              {tr(lang, " · 증적 기록됨 · 해소 시 자동 해제", " · recorded in evidence · clears automatically")}
            </Link>
          )}
          {children}
        </main>
      </div>
      <footer className="flex min-h-6 flex-wrap items-center gap-x-4 bg-navy px-4 py-0.5 text-[11px] text-white/85">
        <span>● {LX(lang, status.mode)}</span>
        <span>profile {LX(lang, status.profile ?? "—")}</span>
        <span>policy {LX(lang, status.policy ?? "—")}</span>
        <span>ledger chain {status.chainOk == null ? "—" : status.chainOk ? "✓" : L(lang, "✗ 불일치")}</span>
        <span>degraded {LX(lang, status.degraded)}</span>
        <span>active agents {LX(lang, status.activeAgents)}/80</span>
        <span className="ml-auto">aegismesh console v0.1.0</span>
      </footer>
    </div>
  );
}

export function PageHeader({ crumb, title, actions }: { crumb: string; title: string; actions?: React.ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-2">
      <div>
        <div className="text-xs text-muted">{crumb}</div>
        <h1 className="mt-1 text-xl font-bold">{title}</h1>
      </div>
      <div className="flex flex-wrap gap-2">{actions}</div>
    </div>
  );
}
