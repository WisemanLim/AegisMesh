// 로그인 강제 (SCR-B02) — 세션 쿠키가 없으면 /login. 토큰 유효성은 API 가 판단한다(만료·회수 → 레이아웃이 /logout).
import { NextResponse, type NextRequest } from "next/server";

const PUBLIC = ["/login", "/login/mfa", "/setup", "/logout", "/auth/sso", "/auth/callback"];   // /setup 하위(첫 실행 ②~⑤)는 로그인 필요

export function middleware(req: NextRequest) {
  const { pathname, search } = req.nextUrl;
  const pass = () => {                                   // 레이아웃이 재인증 화면(MSG-030)으로 보낼 때 돌아올 경로
    const h = new Headers(req.headers);
    h.set("x-aegis-path", pathname + search);
    return NextResponse.next({ request: { headers: h } });
  };
  if (PUBLIC.includes(pathname)) return pass();
  if (req.cookies.get("aegis_session")) return pass();
  const url = new URL("/login", req.url);
  if (pathname !== "/") url.searchParams.set("next", pathname + search);
  return NextResponse.redirect(url);
}

export const config = { matcher: ["/((?!_next/|favicon\\.ico).*)"] };
