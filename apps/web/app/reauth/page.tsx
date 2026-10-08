// SCR-B02 ⑤ 이상 세션 — 새 위치·기기 감지 시 재인증 (MSG-030). 2단계 수단이 있으면 그것으로만, 없으면 비밀번호.
import Link from "next/link";
import { Banner } from "@/components/Badges";
import { PasskeyButton } from "@/components/Passkey";
import { api, safe } from "@/lib/api";
import { tr } from "@/lib/i18n";
import { me, prefs } from "@/lib/session";
import { reauthenticate } from "../login/mfa-actions";

async function reauthForm(form: FormData) {
  "use server";
  await reauthenticate(form);
}

export default async function Reauth({ searchParams }: { searchParams: Promise<{ next?: string; err?: string }> }) {
  const { lang } = await prefs();
  const { next = "/overview", err } = await searchParams;
  const user = await me();
  const { data: o } = await safe(api("/v1/auth/reauth:options", { method: "POST" }), null as any);
  return (
    <main className="w-full max-w-[460px]">
      <div className="mb-6 flex items-center gap-2 text-lg font-bold text-navy"><span aria-hidden className="grid h-8 w-8 place-items-center rounded-full bg-navy text-sm text-white">◆</span> AegisMesh</div>
      <div className="card space-y-4 p-6" data-testid="reauth">
        <h1 className="text-xl font-bold">{tr(lang, "재인증 필요", "Re-authentication required")}</h1>
        <Banner tone="warn">{tr(lang, `새 위치·기기 감지 (MSG-030) — ${user?.reviewReason ?? ""}`, `New location or device detected (MSG-030) — ${user?.reviewReason ?? ""}`)}</Banner>
        {err && <Banner tone="danger">{err}</Banner>}
        {o?.methods?.includes("webauthn") && (
          <PasskeyButton mode="get" publicKey={o.publicKey} action={reauthenticate} fields={{ ticket: o.ticket, next }} testId="passkey-reauth"
            label={tr(lang, "보안 키·패스키로 재인증", "Re-authenticate with security key / passkey")} busyLabel={tr(lang, "보안 키 터치 대기…", "Waiting for the security key…")} />
        )}
        {o?.methods?.includes("totp") && (
          <form action={reauthForm} className="space-y-2 text-sm">
            <input type="hidden" name="ticket" value={o.ticket} /><input type="hidden" name="next" value={next} />
            <label className="block">{tr(lang, "인증 앱 OTP", "Authenticator-app OTP")}<input name="code" required pattern="[0-9]{6}" inputMode="numeric" autoComplete="one-time-code" className="input mono mt-1 w-full" /></label>
            <button className="btn btn-secondary w-full justify-center">{tr(lang, "OTP 로 재인증", "Re-authenticate with OTP")}</button>
          </form>
        )}
        {o?.password && (
          <form action={reauthForm} className="space-y-2 text-sm" data-testid="reauth-password">
            <input type="hidden" name="next" value={next} />
            <label className="block">{tr(lang, "비밀번호 (2단계 수단 미등록)", "Password (no second factor enrolled)")}<input name="password" type="password" required autoComplete="current-password" className="input mt-1 w-full" /></label>
            <button className="btn btn-primary w-full justify-center">{tr(lang, "재인증", "Re-authenticate")}</button>
          </form>
        )}
        <p className="text-xs text-muted">{tr(lang, "본인이 아니면 로그아웃 — 계정의 다른 세션도 내 세션 관리에서 종료", "Not you? Sign out — and end your other sessions in My sessions")} · <Link className="text-primary" href="/logout">{tr(lang, "로그아웃", "Sign out")}</Link></p>
      </div>
    </main>
  );
}
