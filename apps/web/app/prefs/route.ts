// 상단 바의 테넌트 범위·언어 저장. 테넌트 범위는 플랫폼 사용자만 — 볼 수 있는 테넌트인지 API 로 확인한다.
import { NextResponse, type NextRequest } from "next/server";
import { BASE, SESSION_COOKIE, TENANT_COOKIE, apiFetch, authHeaders } from "@/lib/api";

export async function POST(req: NextRequest) {
  const form = await req.formData();
  const host = req.headers.get("x-forwarded-host") ?? req.headers.get("host") ?? req.nextUrl.host;
  const origin = `${req.headers.get("x-forwarded-proto") ?? "http"}://${host}`;
  const ref = req.headers.get("referer");
  const back = ref && new URL(ref).host === host ? ref : "/overview";          // 다른 사이트로 되돌리지 않는다
  const res = NextResponse.redirect(new URL(back, origin), 303);
  const lang = String(form.get("lang") ?? "ko");
  res.cookies.set("lang", lang === "en" ? "en" : "ko", { path: "/", sameSite: "lax" });
  const tenant = form.get("tenant");
  const tok = req.cookies.get(SESSION_COOKIE)?.value;
  if (tenant !== null && tok) {
    const me = await apiFetch(`${BASE}/v1/auth/me`, { headers: await authHeaders("GET", "/v1/auth/me"), cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null)).catch(() => null);
    const v = String(tenant);
    if (me && me.tenant === null && (v === "*" || me.tenants.some((x: { id: string }) => x.id === v))) {
      if (v === "*") res.cookies.delete(TENANT_COOKIE);
      else res.cookies.set(TENANT_COOKIE, v, { path: "/", sameSite: "lax", httpOnly: true });
    }
  }
  return res;
}
