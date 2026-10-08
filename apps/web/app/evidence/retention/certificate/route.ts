// 서명 삭제 증명서 내려받기 (NFR-S) — 원장 공개키로 오프라인 검증.
import { ApiError, api } from "@/lib/api";

export async function GET(req: Request) {
  const id = new URL(req.url).searchParams.get("id") ?? "";
  try {
    const r = await api(`/v1/evidence/purges/${encodeURIComponent(id)}`);
    return new Response(JSON.stringify({ certificate: r.certificate, signature: r.signature, keyId: r.keyId,
      verify: "Ed25519 over sorted compact JSON of `certificate` with the ledger public key (/v1/evidence/public-key)" }, null, 1), {
      headers: { "content-type": "application/json", "content-disposition": `attachment; filename="${id.replace(/[^\w-]/g, "_")}-certificate.json"` } });
  } catch (e) {
    return new Response(JSON.stringify({ error: (e as Error).message }), { status: e instanceof ApiError ? e.status : 502 });
  }
}
