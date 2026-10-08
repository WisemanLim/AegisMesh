"use server";
// 격리 미달 등록 에이전트 차단 승격 요청 (OQ2) — 2인 승인 후 active.
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { ApiError, api } from "@/lib/api";
import { tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";

export async function promoteAgent(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("id"));
  let to = `/catalog/${encodeURIComponent(id)}`;
  try {
    const r = await api(`/v1/agents/${encodeURIComponent(id)}:promote`, { method: "POST", body: JSON.stringify({ reason: String(form.get("reason") ?? "") }) });
    to = `/approvals/${r.approvalRef}`;
  } catch (e) {
    to += `?msg=${encodeURIComponent(tr(lang, `실패 ${e instanceof ApiError ? `${e.status}: ${String(e.detail)}` : (e as Error).message}`, `Failed ${(e as Error).message}`))}`;
  }
  revalidatePath("/", "layout");
  redirect(to);
}
