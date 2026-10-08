// 통제 매핑 보고서 Markdown 내려받기 — 세션 토큰·테넌트 범위·언어(쿠키 lang)를 그대로 API 에 넘긴다 (NFR-C4).
import { type NextRequest } from "next/server";
import { BASE, apiFetch, authHeaders } from "@/lib/api";
import { parseLang } from "@/lib/i18n";

export async function GET(req: NextRequest) {
  const fw = req.nextUrl.searchParams.get("fw") ?? "owasp-llm-2026";
  const lang = parseLang(req.cookies.get("lang")?.value);
  const path = `/v1/reports/${encodeURIComponent(fw)}?format=md&lang=${lang}`;
  const res = await apiFetch(`${BASE}${path}`, { cache: "no-store", headers: await authHeaders("GET", path) });
  return new Response(await res.text(), {
    status: res.status,
    headers: { "content-type": "text/markdown; charset=utf-8", "content-disposition": `attachment; filename="aegismesh-${fw}-${lang}.md"` },
  });
}
