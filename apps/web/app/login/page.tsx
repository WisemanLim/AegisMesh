// SCR-B02 로그인·세션 — 로컬 계정(초기·비상) + 조직 SSO(OIDC) 슬롯. 실패 5회 → 15분 잠금, 세션 8시간·유휴 30분.
import Link from "next/link";
import { redirect } from "next/navigation";
import { Banner } from "@/components/Badges";
import { api, safe } from "@/lib/api";
import { me, prefs } from "@/lib/session";
import { login } from "./actions";

import { L, tr } from "@/lib/i18n";

export default async function Login({ searchParams }: { searchParams: Promise<{ err?: string; msg?: string; next?: string }> }) {
  if (await me()) redirect("/overview");
  const { lang } = await prefs();
  const { err, msg, next = "/overview" } = await searchParams;
  const { data: cfg } = await safe(api("/v1/auth/config", { token: null }), null as any);
  if (cfg?.bootstrapRequired) redirect("/setup");
  const en = lang === "en";
  const sso = !!cfg?.oidc?.enabled;
  return (
    <main className="w-full max-w-[420px]">
      <div className="mb-6 flex items-center gap-2 text-lg font-bold text-navy">
        <span aria-hidden className="grid h-8 w-8 place-items-center rounded-full bg-navy text-sm text-white">◆</span> AegisMesh
      </div>
      <div className="card space-y-4 p-6">
        <h1 className="text-xl font-bold">{en ? "Sign in" : L(lang, "로그인")}</h1>
        {msg && <Banner tone="info">{L(lang, msg)}</Banner>}
        {err && <Banner tone="danger">{L(lang, err)}</Banner>}
        {sso ? (
          <a className="btn btn-primary w-full justify-center" href={`/auth/sso?next=${encodeURIComponent(next)}`} data-testid="sso-login">
            {en ? "Sign in with organization SSO (OIDC)" : L(lang, "조직 SSO 로 로그인 (OIDC)")}
          </a>
        ) : (
          <button className="btn btn-secondary w-full justify-center" disabled title={L(lang, "/admin/sso 에서 연결")}>
            {en ? "Sign in with organization SSO (OIDC) — not configured" : L(lang, "조직 SSO 로 로그인 (OIDC) — 미설정")}
          </button>
        )}
        {sso && <p className="text-xs text-muted">{en ? `Authorization code + PKCE · MFA required · IdP groups → roles. No static password or shared key login.` : L(lang, "인가 코드 + PKCE · MFA 필수 · IdP 그룹→역할. 정적 비밀번호·공유 키 로그인 없음.")}</p>}
        <details open={!sso} className="text-sm">
        {sso && <summary className="cursor-pointer text-xs text-primary">{en ? "Break-glass admin sign-in ›" : L(lang, "비상 관리자 로그인 ›")}</summary>}
        <form action={login} className="mt-2 space-y-3 text-sm">
          <input type="hidden" name="next" value={next} />
          <label className="block">{en ? "User ID" : L(lang, "사용자 ID")}
            <input name="username" required autoComplete="username" className="input mt-1 w-full" />
          </label>
          <label className="block">{en ? "Password" : L(lang, "비밀번호")}
            <input name="password" type="password" required autoComplete="current-password" className="input mt-1 w-full" />
          </label>
          {sso && (
            <label className="block">{en ? "Reason (recorded in ledger, alerts sent)" : L(lang, "사유 (원장 기록·즉시 알림)")}
              <input name="reason" required minLength={4} className="input mt-1 w-full" />
            </label>
          )}
          <button className={`btn ${sso ? "btn-secondary" : "btn-primary"} w-full justify-center`}>{en ? "Sign in" : L(lang, "로그인")}</button>
        </form>
        </details>
        <ul className="space-y-1 text-xs text-muted" data-testid="login-notes">
          <li>{tr(lang, "② 2단계 — 보안 키·패스키(WebAuthn) 우선 · 인증 앱 OTP 대체 (등록한 사용자는 비밀번호 다음 단계)", "② Second factor — security key / passkey (WebAuthn) first · authenticator OTP fallback (after the password for enrolled users)")}</li>
          <li>{tr(lang, "세션은 소유 증명(DPoP) 키에 묶인다 · 새 위치·기기 → 재인증 · 탈취 토큰 재사용 → 세션 전체 폐기·사건", "Sessions are bound to a DPoP proof-of-possession key · new location/device → re-authentication · stolen-token reuse → all sessions revoked + incident")}</li>
          <li>{en ? "Session 8h · idle 30m · lock 15m after 5 failures" : L(lang, "세션 {0}시간 · 유휴 {1}분 · 실패 {2}회 시 15분 잠금", cfg?.session?.ttlHours ?? 8, cfg?.session?.idleMinutes ?? 30, cfg?.lockAfter ?? 5)}</li>
          <li>{en ? "Service accounts use API tokens only — no password login." : L(lang, "서비스 계정은 API 토큰만 — 비밀번호 로그인 없음.")}</li>
          <li>{en ? "Break-glass: " : L(lang, "비상 관리자 분실: ")}<code className="mono">make admin-token RESET=1</code> → <Link className="text-primary" href="/setup">/setup</Link></li>
        </ul>
      </div>
    </main>
  );
}
