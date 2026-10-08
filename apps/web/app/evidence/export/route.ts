// SCR-N05 서명 묶음 내보내기 — 로그인 주체의 테넌트 체인. 검증: python -m aegis verify-bundle <file>
import { type NextRequest } from "next/server";
import { ApiError, api } from "@/lib/api";

export async function GET(req: NextRequest) {
  const q = req.nextUrl.searchParams;
  const qs = new URLSearchParams({ from: q.get("from") ?? "1", ...(q.get("to") ? { to: q.get("to")! } : {}), ...(q.get("chain") ? { chain: q.get("chain")! } : {}) });
  try {
    const body = await api(`/v1/evidence:export?${qs}`);
    return new Response(JSON.stringify(body), {
      headers: { "content-type": "application/json", "content-disposition": `attachment; filename="aegismesh-evidence-${body.chain}-${Date.now()}.json"` },
    });
  } catch (e) {
    const status = e instanceof ApiError ? e.status : 502;
    return new Response(JSON.stringify({ error: (e as Error).message }), { status, headers: { "content-type": "application/json" } });
  }
}
