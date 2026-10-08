"use server";
// 콘솔 서버 액션 — 모든 변경은 로그인 주체(세션 토큰)로 API 를 호출하고, 결과 메시지와 함께 원래 화면으로 돌아간다.
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { ApiError, api } from "@/lib/api";

import { L } from "@/lib/i18n";
import { prefs } from "@/lib/session";
async function call(back: string, path: string, body: unknown, ok: (r: any) => string) {
  const { lang } = await prefs();
  let msg: string;
  try {
    msg = ok(await api(path, { method: "POST", body: JSON.stringify(body ?? {}) }));
  } catch (e) {
    msg = L(lang, "실패 {0}: {1}", e instanceof ApiError ? e.status : "", (e as Error).message);
  }
  revalidatePath("/", "layout");
  redirect(`${back}${back.includes("?") ? "&" : "?"}msg=${encodeURIComponent(msg)}`);
}

export async function incidentAction(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("id")), act = String(form.get("act"));
  await call(`/incidents/${id}`, `/v1/incidents/${id}:${act}`, { note: String(form.get("note") ?? "") }, (r) => `${r.id}: ${act === "contain" ? L(lang, "봉쇄됨") : L(lang, "종결됨")}`);
}

export async function addRisk(form: FormData) {
  const { lang } = await prefs();
  const due = String(form.get("dueAt") || "");
  await call("/risks", "/v1/risks", {
    title: String(form.get("title")), score: form.get("score") ? Number(form.get("score")) : null,
    decision: String(form.get("decision")), owner: String(form.get("owner") || "") || null, dueAt: due ? `${due}T00:00:00Z` : null,
  }, (r) => L(lang, "등록됨 {0}", r.id));
}

export async function registerBundle(form: FormData) {
  const { lang } = await prefs();
  let body: unknown;
  try {
    body = JSON.parse(String(form.get("bundle")));
  } catch {
    redirect(`/catalog/register?msg=${encodeURIComponent("실패: JSON 파싱 오류")}`);
  }
  await call("/catalog/register", "/v1/agents", body, (r) => L(lang, "심사 결과 {0} · {1} ({2})", r.review.outcome, r.id, r.review.id));
}

export async function runScanTarget(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("id"));
  await call("/scan", `/v1/scan-targets/${id}:run`, {}, (r) => `${r.name ?? id}: ${r.verdict}${r.quarantine ? L(lang, " · 격리 {0}", r.quarantine) : ""}`);
}

export async function addScanTarget(form: FormData) {
  const { lang } = await prefs();
  let artifact: any;
  try {
    artifact = JSON.parse(String(form.get("artifact")));
  } catch {
    redirect(`/scan?msg=${encodeURIComponent("실패: artifact JSON 파싱 오류")}`);
  }
  await call("/scan", "/v1/scan-targets", { name: String(form.get("name")), intervalSec: Number(form.get("interval") || 3600), artifact },
    (r) => L(lang, "대상 등록 {0} ({1})", r.id, r.kind));
}

export async function releaseQuarantine(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("id"));
  await call("/scan", `/v1/quarantine/${id}:release`, {}, (r) => r.approvalRef ? L(lang, "격리 해제 승인 요청 {0} (2인)", r.approvalRef) : L(lang, "격리 해제 {0} ({1})", r.id, r.value));
}

export async function runRedteam() {
  const { lang } = await prefs();
  await call("/redteam", "/v1/redteam/campaigns:run", {}, (r) => L(lang, "캠페인 완료: {0}종 · 회귀 {1} · X09 {2}", r.agents, r.regressions.length, r.verdict));
}

export async function runAssess() {
  const { lang } = await prefs();
  await call("/governance", "/v1/governance:assess", {}, (r) => L(lang, "자체 점검 {0} · 발견 {1}건", r.verdict, r.hits.length));
}
