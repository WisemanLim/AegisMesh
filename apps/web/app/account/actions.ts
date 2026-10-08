"use server";
// SCR-B02 내 계정 — 패스키 등록·삭제, 인증 앱 OTP 등록·해제, 다른 세션 종료.
import { cookies, headers } from "next/headers";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { ApiError, api } from "@/lib/api";
import { TOTP_COOKIE, seal } from "@/lib/dpop";
import { tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";

const err = (e: unknown) => (e instanceof ApiError ? `${e.status}: ${typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail)}` : (e as Error).message);

function done(msg: string): never {
  revalidatePath("/account");
  redirect(`/account?msg=${encodeURIComponent(msg)}`);
}

export async function registerPasskey(form: FormData) {
  const { lang } = await prefs();
  let msg: string;
  try {
    const r = await api("/v1/auth/webauthn/register", { method: "POST", body: JSON.stringify({ ticket: String(form.get("ticket")), credential: JSON.parse(String(form.get("credential"))), name: String(form.get("name") || "passkey") }) });
    msg = tr(lang, `패스키 등록 — ${r.name} (${r.alg}) · 다음 로그인부터 2단계`, `Passkey registered — ${r.name} (${r.alg}) · required from the next sign-in`);
  } catch (e) {
    msg = tr(lang, `실패 ${err(e)}`, `Failed ${err(e)}`);
  }
  done(msg);
}

export async function deletePasskey(form: FormData) {
  const { lang } = await prefs();
  let msg: string;
  try {
    await api(`/v1/auth/webauthn/${encodeURIComponent(String(form.get("id")))}`, { method: "DELETE" });
    msg = tr(lang, "패스키 삭제", "Passkey removed");
  } catch (e) {
    msg = tr(lang, `실패 ${err(e)}`, `Failed ${err(e)}`);
  }
  done(msg);
}

export async function totpSetup() {
  const r = await api("/v1/auth/totp:setup", { method: "POST" });
  const secure = (await headers()).get("x-forwarded-proto") === "https";
  // 비밀은 등록 화면에서 한 번만 보여 준다 — 봉인 쿠키 10분, 확인·취소하면 삭제
  (await cookies()).set(TOTP_COOKIE, seal(r), { httpOnly: true, sameSite: "lax", secure, path: "/", maxAge: 600 });
  redirect("/account?totp=setup");
}

export async function totpConfirm(form: FormData) {
  const { lang } = await prefs();
  let msg: string;
  try {
    await api("/v1/auth/totp:confirm", { method: "POST", body: JSON.stringify({ code: String(form.get("code") ?? "").trim() }) });
    (await cookies()).delete(TOTP_COOKIE);
    msg = tr(lang, "인증 앱 OTP 사용 — 패스키가 없을 때의 대체 수단", "Authenticator-app OTP on — fallback when no passkey is at hand");
  } catch (e) {
    msg = tr(lang, `실패 ${err(e)}`, `Failed ${err(e)}`);
  }
  done(msg);
}

export async function totpDisable() {
  const { lang } = await prefs();
  await api("/v1/auth/totp", { method: "DELETE" });
  (await cookies()).delete(TOTP_COOKIE);
  done(tr(lang, "인증 앱 OTP 해제", "Authenticator-app OTP removed"));
}

export async function revokeOthers() {
  const { lang } = await prefs();
  const r = await api("/v1/auth/sessions:revoke-others", { method: "POST" });
  done(tr(lang, `다른 세션 ${r.revoked}개 종료`, `Ended ${r.revoked} other sessions`));
}
