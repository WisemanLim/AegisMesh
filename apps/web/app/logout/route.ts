// 로그아웃 — API 세션 회수 후 쿠키 삭제. 만료·회수된 쿠키 정리에도 쓰인다(레이아웃 → GET /logout).
import { NextResponse, type NextRequest } from "next/server";
import { BASE, SESSION_COOKIE, TENANT_COOKIE, apiFetch, authHeaders } from "@/lib/api";
import { DPOP_COOKIE, MFA_COOKIE } from "@/lib/dpop";

import { L, parseLang } from "@/lib/i18n";
async function logout(req: NextRequest, reason: string) {
  // 라우트 핸들러의 req.url 은 컨테이너 바인드 주소(0.0.0.0)일 수 있다 → 브라우저가 보낸 Host 기준으로 되돌린다.
  const host = req.headers.get("x-forwarded-host") ?? req.headers.get("host") ?? req.nextUrl.host;
  const proto = req.headers.get("x-forwarded-proto") ?? "http";
  const back = `${proto}://${host}/login?msg=${encodeURIComponent(reason)}`;
  let idp: string | null = null;
  if (req.cookies.get(SESSION_COOKIE)?.value) {
    const h = await authHeaders("POST", "/v1/auth/logout").catch(() => ({} as Record<string, string>));
    if (h.Authorization) {
      const r = await apiFetch(`${BASE}/v1/auth/logout`, { method: "POST", headers: { ...h, "content-type": "application/json" }, cache: "no-store",
        body: JSON.stringify({ postLogoutRedirect: back }) }).catch(() => null);
      idp = r?.ok ? ((await r.json().catch(() => null))?.idpLogout ?? null) : null;   // SSO 세션이면 IdP 세션도 끝낸다(RP-Initiated Logout)
    }
  }
  const res = NextResponse.redirect(idp && /^https?:\/\//.test(idp) ? idp : new URL(back), 303);
  res.cookies.delete(SESSION_COOKIE);
  res.cookies.delete(TENANT_COOKIE);
  res.cookies.delete(DPOP_COOKIE);
  res.cookies.delete(MFA_COOKIE);
  return res;
}

const lang = (req: NextRequest) => parseLang(req.cookies.get("lang")?.value);
export const GET = (req: NextRequest) => logout(req, L(lang(req), "세션이 만료되었거나 회수됨 — 다시 로그인"));
export const POST = (req: NextRequest) => logout(req, L(lang(req), "로그아웃됨"));
