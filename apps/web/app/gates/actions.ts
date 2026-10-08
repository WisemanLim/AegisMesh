"use server";
// 관문 재배치 요청(2인 승인)·무시(사유 원장 기록) — SCR-D02.
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { ApiError, api } from "@/lib/api";
import { tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";

async function post(path: string, body: object, ok: (r: any) => string, back: string) {
  const { lang } = await prefs();
  let msg: string;
  try {
    msg = ok(await api(path, { method: "POST", body: JSON.stringify(body) }));
  } catch (e) {
    msg = tr(lang, `실패 ${e instanceof ApiError ? e.status : ""}: ${(e as Error).message}`, `Failed ${e instanceof ApiError ? e.status : ""}: ${(e as Error).message}`);
  }
  revalidatePath("/", "layout");
  redirect(`${back}?msg=${encodeURIComponent(msg)}`);
}

export async function requestRelocation(form: FormData) {
  const { lang } = await prefs();
  const gate = String(form.get("gate"));
  const restore = form.get("restore") === "1";
  await post(`/v1/gates/${gate}/relocations`, { agent: String(form.get("agent")), reason: String(form.get("reason") || (restore ? "인라인 복귀" : "지연 예산 초과")), restore },
    (r) => tr(lang, `요청 ${r.approvalRef} — 2인 승인 후 정책 새 버전으로 반영`, `Requested ${r.approvalRef} — applied as a new policy version after two approvals`), `/gates/${gate}`);
}

export async function ignoreRelocation(form: FormData) {
  const { lang } = await prefs();
  const gate = String(form.get("gate"));
  await post(`/v1/gates/${gate}/relocations:ignore`, { agent: String(form.get("agent")), reason: String(form.get("reason") || "") },
    (r) => tr(lang, `무시 — 원장 #${r.seq} 에 사유 기록`, `Ignored — reason recorded in ledger #${r.seq}`), `/gates/${gate}`);
}
