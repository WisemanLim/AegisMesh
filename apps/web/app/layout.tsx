import "./globals.css";
import type { Metadata } from "next";
import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { Shell, type ShellStatus } from "@/components/Shell";
import { SESSION_COOKIE, api, safe } from "@/lib/api";
import { L } from "@/lib/i18n";
import { LangProvider } from "@/lib/lang";
import { me, prefs } from "@/lib/session";

export async function generateMetadata(): Promise<Metadata> {
  const { lang } = await prefs();
  return { title: L(lang, "AegisMesh 콘솔"), description: L(lang, "AI 에이전트 보안 위험 대응 멀티 에이전트 플랫폼") };
}
export const dynamic = "force-dynamic";

async function status(): Promise<ShellStatus> {
  const [apps, pol, gates, appr, agents, notes] = await Promise.all([
    safe(api("/v1/applications"), { items: [] as any[] }),
    safe(api("/v1/policies/default"), null as any),
    safe(api("/v1/gates:status"), { gates: {} as Record<string, any>, degraded: [] as any[] }),
    safe(api("/v1/approvals"), { items: [] as any[] }),
    safe(api("/v1/agents"), { items: [] as any[] }),
    safe(api("/v1/notifications?hours=24"), { items: [] as any[], counts: {} as Record<string, number> }),
  ]);
  return {
    mode: process.env.AEGIS_MODE ?? "local",
    profile: apps.data.items[0]?.profile ?? null,
    policy: pol.data ? `${pol.data.tenant}/${pol.data.id}@v${pol.data.version}` : null,
    chainOk: null,
    degraded: gates.data.degraded.reduce((n: number, d: any) => n + d.agents.length, 0),
    activeAgents: agents.data.items.filter((a: any) => a.status === "active").length,
    pending: appr.data.items.length,
    gates: gates.data.gates as ShellStatus["gates"],
    degradedGates: gates.data.degraded,
    alerts: (notes.data.counts.critical ?? 0) + (notes.data.counts.high ?? 0) + (notes.data.counts.medium ?? 0),
  };
}

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const { lang } = await prefs();
  if (!(await cookies()).get(SESSION_COOKIE)) {
    // 로그인·첫 실행 화면 (SCR-B02·A06) — 셸 없이 전체 화면
    return (
      <html lang={lang}>
        <body><LangProvider lang={lang}><div className="grid min-h-screen place-items-center bg-[var(--bg)] p-6">{children}</div></LangProvider></body>
      </html>
    );
  }
  const user = await me();
  if (!user) redirect("/logout");
  if (user.reauthRequired || user.enrollRequired) {     // 새 위치·기기(MSG-030) 재인증 · 특권 역할 2단계 등록(OQ3) 전까지 셸·다른 화면 없음
    const path = (await headers()).get("x-aegis-path") ?? "/overview";
    const gate = user.reauthRequired ? "/reauth" : "/enroll";
    if (!path.startsWith(gate)) {
      const to = `${gate}?next=${encodeURIComponent(path.startsWith("/enroll") || path.startsWith("/reauth") ? "/overview" : path.replace(/[?&]_rsc=[^&]*/, ""))}`;
      redirect(`/auth/gate?to=${encodeURIComponent(to)}`);       // 라우트 핸들러 경유 = 전체 페이지 로드
    }
    return (
      <html lang={lang}>
        <body><LangProvider lang={lang}><div className="grid min-h-screen place-items-center bg-[var(--bg)] p-6">{children}</div></LangProvider></body>
      </html>
    );
  }
  return (
    <html lang={lang}>
      <body>
        <LangProvider lang={lang}><Shell lang={lang} me={user} status={await status()}>{children}</Shell></LangProvider>
      </body>
    </html>
  );
}
