"use server";
// 미리보기 표본 보존 설정 (OQ1 · NFR-D1) — 켜기·확대는 2인 승인 요청, 끄기·축소는 바로(끄면 표본 전부 삭제).
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { ApiError, api } from "@/lib/api";
import { tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";

const err = (e: unknown) => (e instanceof ApiError ? `${e.status}: ${typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail)}` : (e as Error).message);

function done(msg: string): never {
  revalidatePath("/", "layout");
  redirect(`/admin/data-protection?msg=${encodeURIComponent(msg)}`);
}

export async function saveSampleRetention(form: FormData) {
  const { lang } = await prefs();
  let msg: string;
  try {
    const r = await api("/v1/traffic-samples/settings", { method: "PUT", body: JSON.stringify({
      enabled: form.get("enabled") === "on", maxSamples: Number(form.get("maxSamples") || 1000), days: Number(form.get("days") || 7) }) });
    msg = r.status === "pending"
      ? tr(lang, `2인 승인 요청 ${r.approvalRef} — 승인 후 마스킹 표본 보존 시작`, `Two-person approval requested ${r.approvalRef} — masked sampling starts after approval`)
      : tr(lang, `적용됨 — ${r.current.enabled ? `최근 ${r.current.maxSamples}건·${r.current.days}일` : "보존 끔"} · 삭제 ${r.removed}건`, `Applied — ${r.current.enabled ? `latest ${r.current.maxSamples} · ${r.current.days} days` : "sampling off"} · removed ${r.removed}`);
  } catch (e) {
    msg = tr(lang, `실패 ${err(e)}`, `Failed ${err(e)}`);
  }
  done(msg);
}

export async function clearSamples() {
  const { lang } = await prefs();
  const r = await api("/v1/traffic-samples", { method: "DELETE" });
  done(tr(lang, `표본 ${r.removed}건 삭제`, `Removed ${r.removed} samples`));
}
