"use server";
// 즉시 사용 마법사 서버 액션 (SCR-C05 보호 대상·연결 시험 · SCR-C07 적용·해제).
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { ApiError, api } from "@/lib/api";
import { tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";

const err = (e: unknown) => (e instanceof ApiError ? `${e.status}: ${typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail)}` : (e as Error).message);

function back(form: FormData, step: string, msg: string, extra: Record<string, string> = {}): never {
  const q = new URLSearchParams();
  for (const k of ["p", "t"]) if (form.get(k)) q.set(k, String(form.get(k)));
  for (const [k, v] of Object.entries(extra)) q.set(k, v);
  q.set("msg", msg);
  revalidatePath("/", "layout");
  redirect(`/instant/${step}?${q}`);
}

export async function saveTarget(form: FormData) {
  const { lang } = await prefs();
  const egress = String(form.get("egress") ?? "").split("\n").map((l) => l.trim()).filter(Boolean).map((l) => {
    const [host, pin] = l.split(/\s+/);
    return { host, pin: pin ?? null };
  });
  const body = {
    name: String(form.get("name") ?? "").trim(), kind: String(form.get("kind") ?? "other"), endpoint: String(form.get("endpoint") ?? "").trim(),
    insertion: String(form.get("insertion") ?? "gateway"), externalModel: form.get("provider") === "external",
    modelProvider: form.get("provider") === "external" ? String(form.get("modelProvider") || "external") : "self-hosted",
    mcpServers: String(form.get("mcpServers") ?? "").split(/[,\s]+/).filter(Boolean), egress,
  };
  let msg: string;
  let t = body.name;
  try {
    const r = await api("/v1/targets", { method: "POST", body: JSON.stringify(body) });
    t = r.name;
    msg = r.approvalRef ? tr(lang, `저장됨 ${r.name} — 외부 모델은 정책상 금지(MSG-013): 승인 요청 ${r.approvalRef} 후 켜짐`, `Saved ${r.name} — external model is denied by policy (MSG-013): approval ${r.approvalRef} pending`)
      : tr(lang, `저장됨 ${r.name}`, `Saved ${r.name}`);
  } catch (e) {
    msg = tr(lang, `실패 ${err(e)}`, `Failed ${err(e)}`);
  }
  form.set("t", t);
  back(form, "targets", msg);
}

export async function deleteTarget(form: FormData) {
  const { lang } = await prefs();
  let msg: string;
  try {
    await api(`/v1/targets/${encodeURIComponent(String(form.get("id")))}`, { method: "DELETE" });
    msg = tr(lang, "삭제됨", "Deleted");
  } catch (e) {
    msg = tr(lang, `실패 ${err(e)}`, `Failed ${err(e)}`);
  }
  back(form, "targets", msg);
}

/** 연결 시험 — 게이트웨이 경유 시험 요청 1건(input 관문). 적용된 프로파일이 없으면 기본 탐지기(d1-01)로 경로만 시험. */
export async function testConnection(form: FormData) {
  const { lang } = await prefs();
  const name = String(form.get("name"));
  const bound = form.get("bound") === "1";
  let msg: string;
  try {
    const r = await api("/v1/judge:batch", { method: "POST", body: JSON.stringify({
      gate: "input", ...(bound ? { target: name } : { agents: ["d1-01"] }),
      request: { text: "AegisMesh connection test — 연결 시험", subject: { principal: { id: name } } } }) });
    msg = tr(lang, `연결 시험 ${name}: ${r.verdict} · ${r.latencyMs ?? "—"}ms · trace ${String(r.traceId).slice(0, 8)}${bound ? "" : " (프로파일 미적용 — 기본 탐지기로 경로 시험)"}`,
      `Connection test ${name}: ${r.verdict} · ${r.latencyMs ?? "—"}ms · trace ${String(r.traceId).slice(0, 8)}${bound ? "" : " (no profile yet — path tested with the default detector)"}`);
  } catch (e) {
    msg = tr(lang, `실패 ${err(e)}`, `Failed ${err(e)}`);
  }
  form.set("t", name);
  back(form, "targets", msg);
}

export async function applyStage(form: FormData) {
  const { lang } = await prefs();
  const stage = String(form.get("stage") ?? "");
  if (!["observe", "partial", "enforce"].includes(stage)) back(form, "apply", tr(lang, "실패 적용 단계를 고른다 (MSG-003)", "Failed choose a stage (MSG-003)"));
  const body = { profile: String(form.get("p")), target: String(form.get("t")), stage, confirmed: form.get("confirmed") === "on",
                 ...(stage === "partial" ? { blockDomains: form.getAll("d").map(String) } : {}) };
  let msg: string;
  try {
    const r = await api("/v1/instant:apply", { method: "POST", body: JSON.stringify(body) });
    msg = r.status === "pending" ? tr(lang, `전체 차단은 승인자 승인 후 적용 — 승인 요청 ${r.approvalRef}`, `Full blocking applies after approval — request ${r.approvalRef}`)
      : tr(lang, `적용됨 ${r.profile} · ${r.stage} · 에이전트 ${r.agents}종 · 정책 10초 내 반영`, `Applied ${r.profile} · ${r.stage} · ${r.agents} agents · live within 10 s`);
  } catch (e) {
    msg = tr(lang, `실패 ${err(e)}`, `Failed ${err(e)}`);
  }
  back(form, "apply", msg, { stage, ...(stage === "partial" ? { d: form.getAll("d").map(String).join(",") } : {}) });
}

export async function rollbackTarget(form: FormData) {
  const { lang } = await prefs();
  let msg: string;
  try {
    const r = await api("/v1/instant:rollback", { method: "POST", body: JSON.stringify({ target: String(form.get("t")) }) });
    msg = r.restored ? tr(lang, `해제됨 — 이전 스냅샷 ${r.restored.profile}(${r.restored.stage}) 으로 복귀`, `Released — restored previous snapshot ${r.restored.profile} (${r.restored.stage})`)
      : tr(lang, "해제됨 — 이전 스냅샷 없음(미적용 상태)", "Released — no previous snapshot (now unprotected)");
  } catch (e) {
    msg = tr(lang, `실패 ${err(e)}`, `Failed ${err(e)}`);
  }
  back(form, "apply", msg);
}

/** 예상 영향 재계산 — 고른 단계·도메인을 쿼리에 실어 같은 화면을 다시 그린다(적용하지 않음). */
export async function recompute(form: FormData) {
  const q = new URLSearchParams();
  for (const k of ["p", "t", "stage"]) if (form.get(k)) q.set(k, String(form.get(k)));
  q.set("d", form.getAll("d").map(String).join(","));
  redirect(`/instant/apply?${q}`);
}
