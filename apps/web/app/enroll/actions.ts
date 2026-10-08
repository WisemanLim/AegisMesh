"use server";
// 2단계 등록 강제 (OQ3) — 특권 역할·테넌트 정책: 등록을 끝내야 세션이 풀린다.
import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { ApiError, api } from "@/lib/api";
import { TOTP_COOKIE, seal } from "@/lib/dpop";
import { LX, tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";

const err = (e: unknown) => (e instanceof ApiError ? (typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail)) : (e as Error).message);
const safeNext = (n: string) => (n.startsWith("/") && !n.startsWith("//") ? n : "/overview");

export async function enrollPasskey(form: FormData): Promise<{ ok: boolean; error?: string } | null> {
  const next = safeNext(String(form.get("next") || "/overview"));
  try {
    await api("/v1/auth/webauthn/register", { method: "POST", body: JSON.stringify({ ticket: String(form.get("ticket")), credential: JSON.parse(String(form.get("credential"))), name: String(form.get("name") || "passkey") }) });
  } catch (e) {
    return { ok: false, error: LX((await prefs()).lang, err(e)) };       // 보안 키 증명 거부 사유도 en 카탈로그로
  }
  redirect(next);
}

export async function enrollTotpStart(form: FormData) {
  const r = await api("/v1/auth/totp:setup", { method: "POST" });
  const secure = (await headers()).get("x-forwarded-proto") === "https";
  (await cookies()).set(TOTP_COOKIE, seal(r), { httpOnly: true, sameSite: "lax", secure, path: "/", maxAge: 600 });
  redirect(`/enroll?totp=1&next=${encodeURIComponent(safeNext(String(form.get("next") || "/overview")))}`);
}

export async function enrollTotpConfirm(form: FormData) {
  const { lang } = await prefs();
  const next = safeNext(String(form.get("next") || "/overview"));
  try {
    await api("/v1/auth/totp:confirm", { method: "POST", body: JSON.stringify({ code: String(form.get("code") ?? "").trim() }) });
  } catch (e) {
    redirect(`/enroll?totp=1&next=${encodeURIComponent(next)}&err=${encodeURIComponent(tr(lang, `실패 ${err(e)}`, `Failed ${err(e)}`))}`);
  }
  (await cookies()).delete(TOTP_COOKIE);
  redirect(next);
}
