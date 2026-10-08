"use server";
// 판정 미리보기·에이전트 시험·이탈 에이전트 종료·레드팀 실행 요청 서버 액션 (SCR-C06·P01~P05·Q02).
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { ApiError, api } from "@/lib/api";

import { L } from "@/lib/i18n";
import { prefs } from "@/lib/session";

type R = { ok: boolean; data?: any; error?: string } | null;
const err = (e: unknown) => (e instanceof ApiError ? `${e.status}: ${typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail)}` : (e as Error).message);

export async function runPreview(_: R, form: FormData): Promise<R> {
  const { lang } = await prefs();
  let samples: any[] | null = null;
  const raw = String(form.get("samples") ?? "").trim();
  if (raw) {
    try {
      samples = raw.split("\n").filter(Boolean).map((l) => JSON.parse(l));
    } catch {
      return { ok: false, error: L(lang, "표본 JSONL 파싱 오류 — 한 줄에 {gate, label, request} 하나") };
    }
  }
  try {
    return { ok: true, data: await api(`/v1/profiles/${encodeURIComponent(String(form.get("profile")))}:preview`, {
      method: "POST", body: JSON.stringify({ stage: String(form.get("stage")), samples, source: String(form.get("source") || "corpus"),
        target: String(form.get("target") || "") || null }) }) };
  } catch (e) {
    return { ok: false, error: err(e) };
  }
}

/** 실제 트래픽 표본 라벨 (정상·공격) — 미리보기 오탐·미탐 추정용 (OQ1). */
export async function labelSample(id: string, label: "benign" | "attack" | null): Promise<R> {
  try {
    return { ok: true, data: await api(`/v1/traffic-samples/${encodeURIComponent(id)}/label`, { method: "PUT", body: JSON.stringify({ label }) }) };
  } catch (e) {
    return { ok: false, error: err(e) };
  }
}

export async function testAgent(_: R, form: FormData): Promise<R> {
  const { lang } = await prefs();
  let request: unknown;
  try {
    request = JSON.parse(String(form.get("request") || "{}"));
  } catch {
    return { ok: false, error: L(lang, "요청 JSON 파싱 오류") };
  }
  try {
    return { ok: true, data: await api("/v1/policies:simulate", { method: "POST", body: JSON.stringify({ gate: String(form.get("gate")), agents: [String(form.get("agent"))], request }) }) };
  } catch (e) {
    return { ok: false, error: err(e) };
  }
}

export async function terminateRogue(form: FormData) {
  const { lang } = await prefs();
  const name = String(form.get("name"));
  let msg: string;
  try {
    const r = await api(`/v1/rogue/${encodeURIComponent(name)}:terminate`, { method: "POST", body: JSON.stringify({ reason: String(form.get("reason") || "이탈 에이전트") }) });
    msg = L(lang, "강제 종료 {0} — 격리 {1} · 토큰 회수 {2} · 신원 폐기 {3}", r.name, r.quarantine, r.tokensRevoked, r.identitiesRevoked.length);
  } catch (e) {
    msg = L(lang, "실패 {0}", err(e));
  }
  revalidatePath("/", "layout");
  redirect(`/extended/x04?msg=${encodeURIComponent(msg)}`);
}

export async function requestRedteam(form: FormData) {
  const { lang } = await prefs();
  const agents = form.getAll("agents").map(String);
  let msg: string;
  try {
    const r = await api("/v1/redteam/campaigns:request", { method: "POST", body: JSON.stringify({ agents: agents.length ? agents : null,
      scenario: String(form.get("scenario")), reason: String(form.get("reason") || "") }) });
    msg = L(lang, "실행 요청 {0} — 승인 대기 (2인 승인 후 실행) · {1}", r.approvalRef, r.scope.isolation);
  } catch (e) {
    msg = L(lang, "실패 {0}", err(e));
  }
  revalidatePath("/", "layout");
  redirect(`/redteam/run?msg=${encodeURIComponent(msg)}`);
}
