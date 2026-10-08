// SCR-B02 조직 SSO 콜백 — code·state 를 API 에 넘겨 토큰 교환(PKCE)·ID 토큰 검증·MFA·그룹→역할 후 세션 쿠키.
import { NextResponse, type NextRequest } from "next/server";
import { ApiError, SESSION_COOKIE, api } from "@/lib/api";
import { requestOrigin, safeNext } from "@/lib/origin";
import { DPOP_COOKIE, newKey, seal } from "@/lib/dpop";
import { sessionCookie } from "@/lib/session";

import { L, parseLang } from "@/lib/i18n";
export async function GET(req: NextRequest) {
  const { base, secure } = requestOrigin(req);
  const sp = req.nextUrl.searchParams;
  const lang = parseLang(req.cookies.get("lang")?.value);
  const fail = (m: string) => NextResponse.redirect(new URL(`/login?err=${encodeURIComponent(m)}`, base), 303);
  if (sp.get("error")) return fail(L(lang, "IdP 거부: {0} {1}", sp.get("error"), sp.get("error_description") ?? "").trim());
  const code = sp.get("code");
  const state = sp.get("state");
  if (!code || !state) return fail(L(lang, "SSO 콜백에 code·state 없음"));
  try {
    const key = newKey();                                 // SSO 세션도 콘솔 DPoP 키에 묶는다 (FR-D5-03)
    const r = await api("/v1/auth/oidc/callback", { method: "POST", token: null, dpopKey: key, body: JSON.stringify({ code, state }) });
    const res = NextResponse.redirect(new URL(safeNext(r.next), base), 303);
    res.cookies.set(SESSION_COOKIE, r.token, sessionCookie(secure));
    res.cookies.set(DPOP_COOKIE, seal(key), sessionCookie(secure));
    return res;
  } catch (e) {
    return fail(e instanceof ApiError ? String(e.detail) : L(lang, "SSO 로그인 실패"));
  }
}
