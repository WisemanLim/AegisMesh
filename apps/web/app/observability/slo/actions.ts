"use server";
// SCR-Q04 품질 서버 액션 — 골든셋 재생 · 공개 공격 코퍼스 반입 재생 · 오탐 예산 점검. 결과는 원장에 남는다.
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { ApiError, api } from "@/lib/api";

import { L, tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";

const err = (e: unknown) => (e instanceof ApiError ? `${e.status}: ${typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail)}` : (e as Error).message);

async function done(msg: string) {
  revalidatePath("/", "layout");
  redirect(`/observability/slo?msg=${encodeURIComponent(msg)}`);
}

export async function runGolden() {
  const { lang } = await prefs();
  let msg: string;
  try {
    const r = await api("/v1/quality/golden:replay", { method: "POST", body: JSON.stringify({ n: 10000 }) });
    msg = L(lang, "골든셋 {0}건 재생 — 오탐률 {1}% · 목표 초과 {2} · {3}ms", r.samples, (r.overallFpRate * 100).toFixed(3), r.overTarget.length ? r.overTarget.join(", ") : L(lang, "없음"), r.durationMs);
  } catch (e) {
    msg = L(lang, "실패 {0}", err(e));
  }
  await done(msg);
}

export async function importCorpus(form: FormData) {
  const { lang } = await prefs();
  let msg: string;
  try {
    const file = form.get("file") as File | null;
    if (!file || file.size === 0) throw new Error(L(lang, "코퍼스 파일(JSONL·CSV) 필요"));
    const name = String(form.get("name") || file.name.replace(/\.[^.]+$/, ""));
    const r = await api("/v1/quality/corpora", {
      method: "POST",
      body: JSON.stringify({ name, source: String(form.get("source") ?? ""), license: String(form.get("license") ?? ""),
        format: file.name.toLowerCase().endsWith(".csv") ? "csv" : "jsonl", mode: String(form.get("mode") || "direct"),
        kind: String(form.get("kind") || "attack"), content: await file.text() }),
    });
    msg = r.kind === "benign"
      ? tr(lang, `정상 코퍼스 ${r.name} ${r.items}건 — 오탐률 ${(r.fpRate * 100).toFixed(2)}% · 페이로드 미보존`, `Benign corpus ${r.name} ${r.items} items — false-positive rate ${(r.fpRate * 100).toFixed(2)}% · payload not kept`)
      : L(lang, "코퍼스 {0} {1}건 — 미탐률 {2}% (목표 ≤ 10% {3}) · 페이로드 미보존", r.name, r.items, (r.missRate * 100).toFixed(1), r.ok ? L(lang, "충족") : L(lang, "초과"));
  } catch (e) {
    msg = L(lang, "실패 {0}", err(e));
  }
  await done(msg);
}

export async function enforceBudget() {
  const { lang } = await prefs();
  let msg: string;
  try {
    const r = await api("/v1/quality/fp-budget:enforce", { method: "POST" });
    msg = L(lang, "오탐 예산 점검 — 조치 {0}", r.actions.length ? r.actions.map((a: any) => `${a.agent} ${a.action}`).join(", ") : L(lang, "없음"));
  } catch (e) {
    msg = L(lang, "실패 {0}", err(e));
  }
  await done(msg);
}
