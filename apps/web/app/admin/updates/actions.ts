"use server";
// SCR-R05 롤링 교체 서버 액션 — 에이전트 1건씩 품질 게이트 통과 시에만 교체(실패 = 기존 유지·자동 롤백).
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { ApiError, api } from "@/lib/api";
import { tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";

export async function reloadAgent(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("id"));
  let msg: string;
  try {
    const r = await api(`/v1/updates/agents/${encodeURIComponent(id)}:reload`, { method: "POST" });
    msg = r.ok ? tr(lang, `${id} 교체 완료 ${r.from} → ${r.to} (품질 게이트 통과 · 관문 재기동 없음)`, `${id} replaced ${r.from} → ${r.to} (quality gate passed · no gate restart)`)
      : tr(lang, `${id} 롤백 — 기존 ${r.from} 유지: ${r.detail ?? ""}`, `${id} rolled back — kept ${r.from}: ${r.detail ?? ""}`);
  } catch (e) {
    msg = tr(lang, `실패 ${e instanceof ApiError ? e.status : ""} ${(e as Error).message}`, `Failed ${e instanceof ApiError ? e.status : ""} ${(e as Error).message}`);
  }
  revalidatePath("/", "layout");
  redirect(`/admin/updates?msg=${encodeURIComponent(msg)}`);
}
