"use server";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { ApiError, api } from "@/lib/api";

import { L } from "@/lib/i18n";
import { prefs } from "@/lib/session";

export async function decide(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("id"));
  let msg: string;
  try {
    const r = await api(`/v1/approvals/${id}:decide`, {
      method: "POST",
      body: JSON.stringify({ decision: String(form.get("decision")), reason: String(form.get("reason") ?? "") }),
    });
    const ok = r.decisions.filter((d: { decision: string }) => d.decision === "approve").length;
    msg = L(lang, "{0}: {1} (승인 {2}/{3})", id, r.status, ok, r.required);
  } catch (e) {
    msg = L(lang, "실패 {0}: {1}", e instanceof ApiError ? e.status : "", (e as Error).message);
  }
  revalidatePath("/", "layout");
  const back = String(form.get("back") || "/approvals");          // 다른 화면(도구 호출 상세 등)에서 결정하면 그 화면으로
  const to = /^\/(?![/\\])/.test(back) ? back : "/approvals";      // 같은 사이트 경로만 (//host·/\host 거부 — 열린 리디렉트 방지)
  redirect(`${to}${to.includes("?") ? "&" : "?"}msg=${encodeURIComponent(msg)}`);
}

// 버튼의 name/value 는 JS 실행 환경의 서버 액션 FormData 에 실리지 않는다 → 결정별 액션을 버튼 formAction 으로 분리.
export async function approve(form: FormData) {
  form.set("decision", "approve");
  return decide(form);
}

export async function reject(form: FormData) {
  form.set("decision", "reject");
  return decide(form);
}
