// 명령 팔레트 검색 (SCR-B05) — 브라우저 → 콘솔 서버 → API (세션 쿠키로 주체 범위 적용).
import { type NextRequest } from "next/server";
import { ApiError, api } from "@/lib/api";

export async function GET(req: NextRequest) {
  const q = req.nextUrl.searchParams.get("q") ?? "";
  if (q.trim().length < 2) return Response.json({});
  try {
    return Response.json(await api(`/v1/search?q=${encodeURIComponent(q)}`));
  } catch (e) {
    return Response.json({ error: (e as Error).message }, { status: e instanceof ApiError ? e.status : 502 });
  }
}
