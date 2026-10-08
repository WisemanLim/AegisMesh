// 시스템·모델 카드 문서 내려받기 (Markdown, ko·en) — SCR-N07.
import { ApiError, api } from "@/lib/api";

export async function GET(req: Request) {
  const u = new URL(req.url);
  const s = u.searchParams.get("s") ?? "";
  const lang = u.searchParams.get("lang") === "en" ? "en" : "ko";
  const v = u.searchParams.get("v");
  try {
    const md = await api<string>(`/v1/compliance/cards/${encodeURIComponent(s)}/doc?lang=${lang}${v ? `&version=${encodeURIComponent(v)}` : ""}`);
    return new Response(md, { headers: { "content-type": "text/markdown; charset=utf-8", "content-disposition": `attachment; filename="${s.replace(/[^\w.-]/g, "_")}-card-${lang}.md"` } });
  } catch (e) {
    return new Response(JSON.stringify({ error: (e as Error).message }), { status: e instanceof ApiError ? e.status : 502 });
  }
}
