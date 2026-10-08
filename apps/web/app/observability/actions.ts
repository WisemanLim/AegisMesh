"use server";
// 마스킹 규칙 시험 (SCR-Q05) — 미리보기(저장 없음) 또는 실제 파이프라인으로 시험 로그 전송.
import { ApiError, api } from "@/lib/api";

type R = { ok: boolean; data?: any; error?: string } | null;

export async function maskTest(_: R, form: FormData): Promise<R> {
  const text = String(form.get("text") ?? "");
  try {
    const path = form.get("send") === "1" ? "/v1/observability:test-log" : "/v1/observability:mask-test";
    return { ok: true, data: { ...(await api(path, { method: "POST", body: JSON.stringify({ text }) })), sent: form.get("send") === "1" } };
  } catch (e) {
    return { ok: false, error: e instanceof ApiError ? `${e.status}: ${String(e.detail)}` : (e as Error).message };
  }
}
