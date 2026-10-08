// 2단계 인증 등록 강제 (OQ3 결정) — 특권 역할(플랫폼·테넌트 관리자·승인자)·테넌트 전원 강제 정책은 첫 수단을 등록해야 콘솔을 쓴다.
import Link from "next/link";
import { cookies } from "next/headers";
import { Banner } from "@/components/Badges";
import { PasskeyButton } from "@/components/Passkey";
import { api, safe } from "@/lib/api";
import { TOTP_COOKIE, unseal } from "@/lib/dpop";
import { tr } from "@/lib/i18n";
import { me, prefs } from "@/lib/session";
import { enrollPasskey, enrollTotpConfirm, enrollTotpStart } from "./actions";

export default async function Enroll({ searchParams }: { searchParams: Promise<{ next?: string; totp?: string; err?: string }> }) {
  const { lang } = await prefs();
  const { next = "/overview", totp, err } = await searchParams;
  const user = await me();
  const [{ data: m }, { data: reg }] = await Promise.all([safe(api("/v1/auth/mfa"), null as any), safe(api("/v1/auth/webauthn/register:options", { method: "POST" }), null as any)]);
  const otp = totp ? unseal<{ secret: string; uri: string }>((await cookies()).get(TOTP_COOKIE)?.value) : null;
  return (
    <main className="w-full max-w-[480px]">
      <div className="mb-6 flex items-center gap-2 text-lg font-bold text-navy"><span aria-hidden className="grid h-8 w-8 place-items-center rounded-full bg-navy text-sm text-white">◆</span> AegisMesh</div>
      <div className="card space-y-4 p-6" data-testid="enroll">
        <h1 className="text-xl font-bold">{tr(lang, "2단계 인증 등록 필요", "Second factor required")}</h1>
        <Banner tone="warn">{m?.policy?.mfa === "all" && !(user?.roles ?? []).some((r) => ["platform_admin", "tenant_admin", "approver"].includes(r))
          ? tr(lang, "테넌트 정책 — 모든 사용자가 2단계 인증을 써야 한다", "Tenant policy — every user must use a second factor")
          : tr(lang, `특권 역할(${(user?.roles ?? []).join(", ")}) — 보안 키·패스키 또는 인증 앱을 먼저 등록한다 (OQ3)`, `Privileged role (${(user?.roles ?? []).join(", ")}) — register a security key / passkey or an authenticator app first (OQ3)`)}</Banner>
        {err && <Banner tone="danger">{err}</Banner>}
        {reg?.publicKey && (
          <div className="space-y-1">
            <div className="text-sm font-semibold">{tr(lang, "① 보안 키·패스키 (권장)", "① Security key / passkey (recommended)")}</div>
            <PasskeyButton mode="create" publicKey={reg.publicKey} action={enrollPasskey} fields={{ ticket: reg.ticket, next }} needName testId="enroll-passkey"
              namePlaceholder={tr(lang, "이름 (예: 업무 노트북)", "Name (e.g. work laptop)")} label={tr(lang, "등록", "Register")} busyLabel={tr(lang, "보안 키 터치 대기…", "Waiting for the key…")} className="btn btn-primary h-8 text-xs" />
            {reg.aaguidAllowlist?.length > 0 && <p className="text-xs text-muted">{tr(lang, `테넌트 허용 인증기만 (AAGUID ${reg.aaguidAllowlist.length}종)`, `Only the tenant's allowed authenticators (${reg.aaguidAllowlist.length} AAGUIDs)`)}</p>}
          </div>
        )}
        <div className="space-y-1 text-sm">
          <div className="font-semibold">{tr(lang, "② 인증 앱 OTP (대체)", "② Authenticator-app OTP (fallback)")}</div>
          {otp ? (
            <form action={enrollTotpConfirm} className="space-y-1 text-xs" data-testid="enroll-totp">
              <input type="hidden" name="next" value={next} />
              <div>{tr(lang, "인증 앱에 추가 (이 화면에서만 보인다):", "Add to your authenticator app (shown only here):")}</div>
              <code className="mono block break-all rounded bg-line/40 p-1" data-testid="enroll-totp-secret">{otp.secret}</code>
              <div className="flex gap-1"><input name="code" required pattern="[0-9]{6}" inputMode="numeric" autoComplete="one-time-code" className="input mono h-7 flex-1" placeholder="123456" aria-label="otp code" /><button className="btn btn-secondary h-7">{tr(lang, "확인", "Confirm")}</button></div>
            </form>
          ) : <form action={enrollTotpStart}><input type="hidden" name="next" value={next} /><button className="btn btn-secondary h-8 text-xs" data-testid="enroll-totp-start">{tr(lang, "인증 앱으로 등록", "Use an authenticator app")}</button></form>}
        </div>
        <p className="text-xs text-muted">{tr(lang, "등록을 마치면 이번 세션이 바로 풀리고, 다음 로그인부터 2단계를 묻는다.", "Once registered this session unlocks immediately; the next sign-in asks for the second factor.")} · <Link className="text-primary" href="/logout">{tr(lang, "로그아웃", "Sign out")}</Link></p>
      </div>
    </main>
  );
}
