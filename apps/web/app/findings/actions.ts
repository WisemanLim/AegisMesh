"use server";
// SCR-O02 판정 이의·재판정 서버 액션 — 접수(신청자) → 결정(다른 사람). 원장 기록은 API 가 한다.
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { ApiError, api } from "@/lib/api";

import { L } from "@/lib/i18n";
import { prefs } from "@/lib/session";

const err = (e: unknown) => (e instanceof ApiError ? `${e.status}: ${typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail)}` : (e as Error).message);

export async function appealFinding(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("id"));
  let msg: string;
  try {
    const raw = String(form.get("sample") ?? "").trim();
    let sample: unknown = null;
    if (raw) {
      try {
        sample = JSON.parse(raw);
      } catch {
        throw new Error(L(lang, "재현 표본은 JSON — 예: {\"output\": \"마스킹한 문장\"}"));
      }
    }
    const r = await api(`/v1/findings/${id}:appeal`, {
      method: "POST",
      body: JSON.stringify({ reason: form.get("reason"), method: form.get("method"), detail: String(form.get("detail") ?? ""), sample }),
    });
    msg = L(lang, "이의 접수 {0}{1}", r.id, r.rejudge?.agent ? L(lang, " — 교차 재판정: 원 에이전트 {0}, 같은 계열 {1}종 합의 {2}", r.rejudge.agent.verdict, r.rejudge.peers.length, r.rejudge.consensus) : "");
  } catch (e) {
    msg = L(lang, "실패 {0}", err(e));
  }
  revalidatePath("/", "layout");
  redirect(`/findings/${id}?msg=${encodeURIComponent(msg)}`);
}

export async function decideAppeal(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("finding"));
  let msg: string;
  try {
    const r = await api(`/v1/appeals/${form.get("appeal")}:decide`, {
      method: "POST", body: JSON.stringify({ label: form.get("label"), note: String(form.get("note") ?? "") }),
    });
    const acts = (r.budget ?? []).map((a: any) => `${a.agent} ${a.action}`).join(", ");
    msg = L(lang, "이의 결정 — {0}{1}{2}", r.label.label === "fp" ? L(lang, "오탐 확정") : L(lang, "정탐 유지"), r.label.sampleId ? L(lang, " · 골든셋 편입 {0}", r.label.sampleId) : "", acts ? L(lang, " · 오탐 예산: {0}", acts) : "");
  } catch (e) {
    msg = L(lang, "실패 {0}", err(e));
  }
  revalidatePath("/", "layout");
  redirect(`/findings/${id}?msg=${encodeURIComponent(msg)}`);
}
