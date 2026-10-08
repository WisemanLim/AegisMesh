"use server";
import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { ApiError, SESSION_COOKIE, api } from "@/lib/api";
import { DPOP_COOKIE, MFA_COOKIE, newKey, seal } from "@/lib/dpop";
import { sessionCookie } from "@/lib/session";

import { L } from "@/lib/i18n";
import { prefs } from "@/lib/session";

const safeNext = (n: string) => (n.startsWith("/") && !n.startsWith("//") ? n : "/overview");

async function secure() {
  return (await headers()).get("x-forwarded-proto") === "https";
}

export async function login(form: FormData) {
  const { lang } = await prefs();
  const next = safeNext(String(form.get("next") || "/overview"));
  const key = newKey();                                   // 이 세션의 DPoP 키 (SCR-B02 · FR-D5-03)
  let r: any = null;
  let err = "";
  try {
    r = await api("/v1/auth/login", {
      method: "POST", token: null, dpopKey: key,
      body: JSON.stringify({ username: String(form.get("username") ?? ""), password: String(form.get("password") ?? ""), reason: String(form.get("reason") ?? "") }),
    });
  } catch (e) {
    err = e instanceof ApiError ? String(e.detail) : L(lang, "로그인 실패");
  }
  if (err) redirect(`/login?err=${encodeURIComponent(err)}&next=${encodeURIComponent(next)}`);
  const jar = await cookies();
  const sec = await secure();
  if (r.mfa) {                                            // ② 2단계 — 패스키 우선 · OTP 대체
    jar.set(MFA_COOKIE, seal({ ticket: r.mfa.ticket, pk: r.mfa.publicKey, methods: r.mfa.methods, key, next }), { ...sessionCookie(sec), maxAge: 300 });
    redirect("/login/mfa");
  }
  jar.set(SESSION_COOKIE, r.token, sessionCookie(sec));
  jar.set(DPOP_COOKIE, seal(key), sessionCookie(sec));
  if (r.enrollRequired) redirect(`/auth/gate?to=${encodeURIComponent(`/enroll?next=${encodeURIComponent(next)}`)}`);   // OQ3 — 등록 전용 세션
  redirect(next);
}

export async function bootstrap(form: FormData) {
  const { lang } = await prefs();
  const pw = String(form.get("password") ?? "");
  if (pw !== String(form.get("password2") ?? "")) redirect(`/setup?err=${encodeURIComponent("비밀번호 확인이 다르다")}`);
  let token = "";
  let err = "";
  const bkey = newKey();
  try {
    const r = await api("/v1/auth/bootstrap", {
      method: "POST", token: null, dpopKey: bkey,
      body: JSON.stringify({
        token: String(form.get("token") ?? "").trim(), username: String(form.get("username") ?? ""),
        displayName: String(form.get("displayName") ?? ""), password: pw,
        tenantId: String(form.get("tenantId") || "default"), tenantName: String(form.get("tenantName") ?? ""),
        lang: String(form.get("lang") ?? "ko"),
      }),
    });
    token = r.token;
  } catch (e) {
    err = e instanceof ApiError ? (typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail)) : L(lang, "설정 실패");
  }
  if (err) redirect(`/setup?err=${encodeURIComponent(err)}`);
  const jar = await cookies();
  jar.set(SESSION_COOKIE, token, sessionCookie(await secure()));
  jar.set(DPOP_COOKIE, seal(bkey), sessionCookie(await secure()));
  jar.set("lang", String(form.get("lang") ?? "ko") === "en" ? "en" : "ko", { path: "/", sameSite: "lax" });
  redirect(`/setup/identity?msg=${encodeURIComponent(L(String(form.get("lang")) === "en" ? "en" : "ko", "① 완료 — 비상 관리자 생성·부트스트랩 토큰 폐기. 다음: 신원·비밀"))}`);
}
