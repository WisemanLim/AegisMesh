// SCR-B02 ② 2단계 인증 — 보안 키·패스키(WebAuthn) 우선, 인증 앱 OTP 대체. 실패 5회 → 15분 잠금. 대기 5분.
import Link from "next/link";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { Banner } from "@/components/Badges";
import { PasskeyButton } from "@/components/Passkey";
import { MFA_COOKIE, unseal } from "@/lib/dpop";
import { tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";
import { type MfaState, verifyMfa } from "../mfa-actions";

async function verifyOtp(form: FormData) {
  "use server";
  await verifyMfa(form);
}

export default async function Mfa() {
  const { lang } = await prefs();
  const st = unseal<MfaState>((await cookies()).get(MFA_COOKIE)?.value);
  if (!st) redirect(`/login?err=${encodeURIComponent(tr(lang, "2단계 대기 시간이 지났다 — 다시 로그인", "The second step expired — sign in again"))}`);
  return (
    <main className="w-full max-w-[420px]">
      <div className="mb-6 flex items-center gap-2 text-lg font-bold text-navy"><span aria-hidden className="grid h-8 w-8 place-items-center rounded-full bg-navy text-sm text-white">◆</span> AegisMesh</div>
      <div className="card space-y-4 p-6" data-testid="mfa">
        <h1 className="text-xl font-bold">{tr(lang, "② 2단계 인증", "② Second factor")}</h1>
        <Banner tone="info">{tr(lang, "보안 키·패스키(WebAuthn) 우선 · 인증 앱 OTP 대체 · 실패 5회 시 15분 잠금", "Security key / passkey (WebAuthn) first · authenticator-app OTP as fallback · 5 failures lock for 15 min")}</Banner>
        {st.methods.includes("webauthn") && (
          <PasskeyButton mode="get" publicKey={st.pk} action={verifyMfa} testId="passkey-login"
            label={tr(lang, "보안 키·패스키로 인증", "Verify with security key / passkey")} busyLabel={tr(lang, "보안 키 터치 대기…", "Waiting for the security key…")} />
        )}
        {st.methods.includes("totp") && (
          <form action={verifyOtp} className="space-y-2 text-sm" data-testid="otp-form">
            <label className="block">{tr(lang, "인증 앱 OTP (6자리)", "Authenticator-app OTP (6 digits)")}
              <input name="code" required inputMode="numeric" pattern="[0-9]{6}" autoComplete="one-time-code" className="input mono mt-1 w-full" /></label>
            <button className={`btn ${st.methods.includes("webauthn") ? "btn-secondary" : "btn-primary"} w-full justify-center`}>{tr(lang, "OTP 로 인증", "Verify with OTP")}</button>
          </form>
        )}
        <ul className="space-y-1 text-xs text-muted">
          <li>{tr(lang, "세션은 이 콘솔의 소유 증명(DPoP) 키에 묶인다 — 토큰만 빼내 쓰면 세션 전체 폐기·사건", "The session is bound to this console's proof-of-possession (DPoP) key — reusing a stolen token revokes every session and opens an incident")}</li>
          <li><Link className="text-primary" href="/logout">{tr(lang, "처음부터 다시", "Start over")}</Link></li>
        </ul>
      </div>
    </main>
  );
}
