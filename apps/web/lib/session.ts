import { cookies } from "next/headers";
import { cache } from "react";
import { ApiError, SESSION_COOKIE, api } from "@/lib/api";
import { parseLang, type Lang } from "@/lib/i18n";

export type Me = {
  id: string; username: string; displayName: string; roles: string[]; tenant: string | null; scope: string;
  permissions: string[]; tenants: { id: string; name: string }[]; roleNames: Record<string, string>; breakGlass: boolean; session: string;
  reauthRequired?: boolean; enrollRequired?: boolean; reviewReason?: string | null; binding?: { dpop: boolean; mfa: string | null; device: string | null; location: string | null } | null;
};

export async function prefs(): Promise<{ lang: Lang }> {
  const c = await cookies();
  return { lang: parseLang(c.get("lang")?.value) };
}

/** 현재 로그인 주체 (요청 단위 캐시). 세션 쿠키가 없거나 만료·회수면 null. */
export const me = cache(async (): Promise<Me | null> => {
  if (!(await cookies()).get(SESSION_COOKIE)) return null;
  try {
    return await api<Me>("/v1/auth/me");
  } catch (e) {
    if (e instanceof ApiError && (e.status === 401 || e.status === 403 || e.status === 404)) return null;
    throw e;
  }
});

export const can = (m: Me | null, perm: string) => !!m?.permissions.includes(perm);

/** 로그인 쿠키 — https 뒤(x-forwarded-proto)면 Secure. 세션 수명 8시간(API 와 동일). */
export function sessionCookie(secure: boolean) {
  return { httpOnly: true, sameSite: "lax" as const, secure, path: "/", maxAge: 8 * 3600 };
}
