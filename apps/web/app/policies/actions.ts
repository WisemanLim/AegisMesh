"use server";
// 관문·정책 서버 액션 (SCR-D03·D04·D05·C08). 시험·시뮬레이션·검증은 저장하지 않는다 — 결과는 액션 상태로 돌려준다.
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { ApiError, api } from "@/lib/api";

import { L } from "@/lib/i18n";
import { prefs } from "@/lib/session";

type R = { ok?: boolean; error?: string; data?: any } | null;
const YAML = { "content-type": "application/yaml" };

async function run(p: Promise<any>): Promise<R> {
  try {
    return { ok: true, data: await p };
  } catch (e) {
    if (e instanceof ApiError) return { ok: false, error: typeof e.detail === "string" ? e.detail : (e.detail as any)?.detail ?? JSON.stringify(e.detail), data: e.detail };
    return { ok: false, error: (e as Error).message };
  }
}

export async function testPolicy(_: R, form: FormData): Promise<R> {
  return run(api("/v1/policies:test", { method: "POST", headers: YAML, body: String(form.get("yaml") ?? "") }));
}

export async function deployPolicy(_: R, form: FormData): Promise<R> {
  const r = await run(api("/v1/policies", { method: "POST", headers: YAML, body: String(form.get("yaml") ?? "") }));
  revalidatePath("/", "layout");
  return r;
}

export async function simulate(_: R, form: FormData): Promise<R> {
  const { lang } = await prefs();
  let request: unknown;
  try {
    request = JSON.parse(String(form.get("request") || "{}"));
  } catch {
    return { ok: false, error: L(lang, "요청 JSON 파싱 오류") };
  }
  const agents = String(form.get("agents") ?? "").split(",").map((x) => x.trim()).filter(Boolean);
  const draft = String(form.get("draft") ?? "").trim();
  return run(api("/v1/policies:simulate", {
    method: "POST",
    body: JSON.stringify({ gate: String(form.get("gate")), request, target: String(form.get("target") || "") || null,
      agents: agents.length ? agents : null, stage: String(form.get("stage") || "") || null, draft: draft || null }),
  }));
}

export async function validateProfile(_: R, form: FormData): Promise<R> {
  return run(api("/v1/profiles:validate", { method: "POST", headers: YAML, body: String(form.get("yaml") ?? "") }));
}

export async function saveProfile(_: R, form: FormData): Promise<R> {
  const r = await run(api("/v1/profiles", { method: "POST", headers: YAML, body: String(form.get("yaml") ?? "") }));
  revalidatePath("/", "layout");
  return r;
}

export async function requestRollback(form: FormData) {
  const { lang } = await prefs();
  const pid = String(form.get("policy"));
  let msg: string;
  try {
    const r = await api(`/v1/policies/${pid}:rollback`, { method: "POST", body: JSON.stringify({ to: Number(form.get("target")), reason: String(form.get("reason") ?? "") }) });
    msg = L(lang, "롤백 요청 {0} — 승인 대기 (2인 승인 후 적용)", r.approvalRef);
  } catch (e) {
    msg = L(lang, "실패 {0}: {1}", e instanceof ApiError ? e.status : "", (e as Error).message);
  }
  revalidatePath("/", "layout");
  redirect(`/policies?p=${encodeURIComponent(pid)}&msg=${encodeURIComponent(msg)}`);
}

// 에이전트 설정 (정책 agentParams — 도메인 상세 화면 공통). 시험은 저장하지 않고, 배포는 사유와 함께 새 정책 버전.
const overrides = (form: FormData) => ({ ...(form.get("overrides") ? { overrides: JSON.parse(String(form.get("overrides"))) } : {}),
  ...(form.get("principal") ? { principal: String(form.get("principal")) } : {}) });
export async function testAgentConfig(_: R, form: FormData): Promise<R> {
  const { lang } = await prefs();
  const raw = String(form.get("sample") ?? "").trim();
  let sample: unknown = null;
  if (raw) {
    try {
      sample = JSON.parse(raw);
    } catch {
      return { ok: false, error: L(lang, "요청 JSON 파싱 오류") };
    }
  }
  return run(api(`/v1/agents/${encodeURIComponent(String(form.get("agent")))}/config:test`, {
    method: "POST", body: JSON.stringify({ values: JSON.parse(String(form.get("values") || "{}")), sample, ...overrides(form) }),
  }));
}

export async function saveAgentConfig(_: R, form: FormData): Promise<R> {
  const r = await run(api(`/v1/agents/${encodeURIComponent(String(form.get("agent")))}/config`, {
    method: "PUT", body: JSON.stringify({ values: JSON.parse(String(form.get("values") || "{}")), reason: String(form.get("reason") ?? ""), ...overrides(form) }),
  }));
  revalidatePath("/", "layout");
  return r;
}
