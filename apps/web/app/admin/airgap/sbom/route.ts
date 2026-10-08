// 제품 자체 릴리스 SBOM (CycloneDX) 내려받기 — SCR-R05 #8.
import { ApiError, api } from "@/lib/api";

export async function GET() {
  try {
    const r = await api("/v1/sbom");
    return new Response(JSON.stringify(r.sbom, null, 1), {
      headers: { "content-type": "application/vnd.cyclonedx+json", "content-disposition": 'attachment; filename="aegismesh-sbom.cdx.json"' },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: (e as Error).message }), { status: e instanceof ApiError ? e.status : 502 });
  }
}
