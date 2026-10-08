"use server";
// SCR-B02 ② 2단계 인증 · ⑤ 재인증 서버 액션 — 1단계에서 만든 DPoP 키로 2단계 요청에도 증명을 싣고, 성공하면 세션 쿠키 + 봉인 키 쿠키.
import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { ApiError, SESSION_COOKIE, api } from "@/lib/api";
import { DPOP_COOKIE, MFA_COOKIE, seal, unseal } from "@/lib/dpop";
import { tr } from "@/lib/i18n";
import { prefs, sessionCookie } from "@/lib/session";

type R = { ok: boolean; error?: string } | null;
const err = (e: unknown) => (e instanceof ApiError ? (typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail)) : (e as Error).message);
const safeNext = (n: string) => (n.startsWith("/") && !n.startsWith("//") ? n : "/overview");

export type MfaState = { ticket: string; pk: any; methods: string[]; key: any; next: string };

export async function verifyMfa(form: FormData): Promise<R> {
  const { lang } = await prefs();
  const jar = await cookies();
  const st = unseal<MfaState>(jar.get(MFA_COOKIE)?.value);
  if (!st) return { ok: false, error: tr(lang, "2단계 대기 시간(5분)이 지났다 — 다시 로그인", "The second-step window (5 min) expired — sign in again") };
  const cred = form.get("credential");
  const code = form.get("code");
  let token = "";
  try {
    const r = await api("/v1/auth/mfa:verify", { method: "POST", token: null, dpopKey: st.key,
      body: JSON.stringify({ ticket: st.ticket, ...(cred ? { credential: JSON.parse(String(cred)) } : {}), ...(code ? { code: String(code).trim() } : {}) }) });
    token = r.token;
  } catch (e) {
    jar.delete(MFA_COOKIE);                       // 대기표는 1회용 — 실패하면 처음부터
    redirect(`/login?err=${encodeURIComponent(err(e))}&next=${encodeURIComponent(st.next)}`);
  }
  const secure = (await headers()).get("x-forwarded-proto") === "https";
  jar.set(SESSION_COOKIE, token, sessionCookie(secure));
  jar.set(DPOP_COOKIE, seal(st.key), sessionCookie(secure));
  jar.delete(MFA_COOKIE);
  redirect(safeNext(st.next));
}

export async function reauthenticate(form: FormData): Promise<R> {
  const { lang } = await prefs();
  const next = safeNext(String(form.get("next") || "/overview"));
  const cred = form.get("credential");
  try {
    await api("/v1/auth/reauth", { method: "POST", body: JSON.stringify({ ticket: form.get("ticket") || null, ...(cred ? { credential: JSON.parse(String(cred)) } : {}),
      ...(form.get("code") ? { code: String(form.get("code")).trim() } : {}), ...(form.get("password") ? { password: String(form.get("password")) } : {}) }) });
  } catch (e) {
    redirect(`/reauth?next=${encodeURIComponent(next)}&err=${encodeURIComponent(tr(lang, `재인증 실패 — ${err(e)}`, `Re-authentication failed — ${err(e)}`))}`);
  }
  redirect(next);
}
