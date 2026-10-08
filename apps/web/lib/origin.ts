// 라우트 핸들러의 req.url 은 컨테이너 바인드 주소(0.0.0.0)일 수 있다 → 브라우저가 보낸 Host 기준 원점.
import type { NextRequest } from "next/server";

export function requestOrigin(req: NextRequest): { base: string; secure: boolean } {
  const host = req.headers.get("x-forwarded-host") ?? req.headers.get("host") ?? req.nextUrl.host;
  const proto = req.headers.get("x-forwarded-proto") ?? "http";
  return { base: `${proto}://${host}`, secure: proto === "https" };
}

export const safeNext = (n: string | null | undefined) => (n && n.startsWith("/") && !n.startsWith("//") ? n : "/overview");
