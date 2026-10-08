"use server";
// 성공 지표 스냅샷 — 전체 원장 검증 포함(오래 걸릴 수 있음).
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { ApiError, api } from "@/lib/api";
import { tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";

export async function snapshotNow() {
  const { lang } = await prefs();
  let msg: string;
  try {
    const r = await api("/v1/metrics/success:snapshot", { method: "POST" });
    msg = tr(lang, `기록됨 #${r.seq} — 원장 검증 ${r.integrity.ok ? "통과" : "실패"} (${r.integrity.records}건) · 측정 ${r.summary.measured}/${r.summary.total}`,
      `Recorded #${r.seq} — ledger verification ${r.integrity.ok ? "passed" : "failed"} (${r.integrity.records} records) · measured ${r.summary.measured}/${r.summary.total}`);
  } catch (e) {
    msg = tr(lang, `실패 ${e instanceof ApiError ? e.status : ""} ${(e as Error).message}`, `Failed ${e instanceof ApiError ? e.status : ""} ${(e as Error).message}`);
  }
  revalidatePath("/success");
  redirect(`/success?msg=${encodeURIComponent(msg)}`);
}
