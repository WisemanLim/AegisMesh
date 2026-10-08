// 제품 자체 릴리스 SBOM(CycloneDX) + 분리형 서명 내려받기 — SCR-R05 #8. 서명 검증 키 = /v1/identity/jwks.
import { ApiError, api } from "@/lib/api";

export async function GET() {
  try {
    const r = await api("/v1/updates/sbom");
    return new Response(JSON.stringify({ sbom: r.sbom, signature: r.signature }, null, 1), {
      headers: { "content-type": "application/json", "content-disposition": 'attachment; filename="aegismesh-sbom.signed.json"' },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: (e as Error).message }), { status: e instanceof ApiError ? e.status : 502 });
  }
}
