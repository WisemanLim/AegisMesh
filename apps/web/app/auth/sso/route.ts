// SCR-B02 #1 조직 SSO 로그인 시작 — API 가 state·nonce·PKCE code_verifier 를 서버에 두고 IdP 인가 URL 만 돌려준다.
import { NextResponse, type NextRequest } from "next/server";
import { ApiError, api } from "@/lib/api";
import { requestOrigin, safeNext } from "@/lib/origin";

import { L, parseLang } from "@/lib/i18n";
export async function GET(req: NextRequest) {
  const { base } = requestOrigin(req);
  const next = safeNext(req.nextUrl.searchParams.get("next"));
  try {
    const q = new URLSearchParams({ redirect: `${base}/auth/callback`, next });
    const r = await api(`/v1/auth/oidc/start?${q}`, { token: null });
    return NextResponse.redirect(r.url, 303);
  } catch (e) {
    const msg = e instanceof ApiError ? String(e.detail) : L(parseLang(req.cookies.get("lang")?.value), "SSO 시작 실패");
    return NextResponse.redirect(new URL(`/login?err=${encodeURIComponent(msg)}&next=${encodeURIComponent(next)}`, base), 303);
  }
}
