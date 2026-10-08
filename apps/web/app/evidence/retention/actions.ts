"use server";
// 증적 보존기한 만료 — 2인 승인 배치 요청 (삭제 API 아님, NFR-S).
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { ApiError, api } from "@/lib/api";
import { tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";

export async function requestPurge(form: FormData) {
  const { lang } = await prefs();
  let msg: string;
  try {
    const r = await api("/v1/evidence/retention:request", { method: "POST", body: JSON.stringify({ chain: String(form.get("chain")) }) });
    msg = tr(lang, `2인 승인 요청 ${r.approvalRef} — seq ${r.plan.fromSeq}~${r.plan.throughSeq} ${r.plan.purge}건, 승인 뒤 배치가 지우고 서명 삭제 증명을 남긴다`,
      `Two-person approval requested ${r.approvalRef} — seq ${r.plan.fromSeq}–${r.plan.throughSeq}, ${r.plan.purge} records; the batch deletes after approval and leaves a signed certificate`);
  } catch (e) {
    msg = tr(lang, `실패 ${e instanceof ApiError ? `${e.status}: ${String(e.detail)}` : (e as Error).message}`, `Failed ${e instanceof ApiError ? `${e.status}: ${String(e.detail)}` : (e as Error).message}`);
  }
  revalidatePath("/evidence/retention");
  redirect(`/evidence/retention?msg=${encodeURIComponent(msg)}`);
}
