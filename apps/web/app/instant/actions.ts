"use server";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { api } from "@/lib/api";

import { L } from "@/lib/i18n";
import { prefs } from "@/lib/session";

export async function applyProfile(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("profile"));
  let msg = "";
  try {
    const r = await api(`/v1/profiles/${id}:apply`, {
      method: "POST",
      body: JSON.stringify({ target: String(form.get("target") || "default-target"), stage: String(form.get("stage")) }),
    });
    msg = L(lang, "적용됨 {0} · 에이전트 {1}종 · 미구현 {2}항목", r.id, r.agents.length, r.missing.length);
  } catch (e) {
    msg = L(lang, "실패: {0}", (e as Error).message);
  }
  revalidatePath("/", "layout");
  redirect(`/instant?msg=${encodeURIComponent(msg)}`);
}

export async function releaseApplication(form: FormData) {
  await api(`/v1/applications/${String(form.get("id"))}:release`, { method: "POST" });
  revalidatePath("/", "layout");
  redirect(`/instant?msg=${encodeURIComponent(L((await prefs()).lang, "해제됨"))}`);
}
