"use server";
// 도메인 상세 화면 서버 액션 — 검사기(저장 없음)·교차 조회 회귀·삭제 전파·학습 데이터 재현 시험.
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { ApiError, api } from "@/lib/api";
import { tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";

type R = { ok?: boolean; error?: string; data?: any } | null;
const err = (e: unknown) => (e instanceof ApiError ? (typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail)) : (e as Error).message);

export async function inspectAgent(_: R, form: FormData): Promise<R> {
  const { lang } = await prefs();
  let request: unknown;
  try {
    request = JSON.parse(String(form.get("request") || "{}"));
  } catch {
    return { ok: false, error: tr(lang, "요청 JSON 파싱 오류", "Request JSON parse error") };
  }
  try {
    return { ok: true, data: await api(`/v1/agents/${encodeURIComponent(String(form.get("agent")))}:inspect`, { method: "POST", body: JSON.stringify({ request }) }) };
  } catch (e) {
    return { ok: false, error: err(e) };
  }
}

async function go(back: string, p: Promise<any>, ok: (r: any) => string) {
  const { lang } = await prefs();
  let msg: string;
  try {
    msg = ok(await p);
  } catch (e) {
    msg = tr(lang, `실패: ${err(e)}`, `Failed: ${err(e)}`);
  }
  revalidatePath("/", "layout");
  redirect(`${back}${back.includes("?") ? "&" : "?"}msg=${encodeURIComponent(msg)}`);
}

export async function runRegression(form: FormData) {
  const { lang } = await prefs();
  await go("/domains/d2/isolation", api(`/v1/domains/d2/isolation:regress?n=${Number(form.get("n")) || 100}`, { method: "POST" }),
    (r) => tr(lang, `교차 조회 회귀 ${r.ok ? "통과" : "누출 발견"} — ${r.cases.map((c: any) => `${c.case} ${c.leaked}/${c.probes}`).join(" · ")} (원장 #${r.seq})`,
      `Cross-scope regression ${r.ok ? "passed" : "leak found"} — ${r.cases.map((c: any) => `${c.case} ${c.leaked}/${c.probes}`).join(" · ")} (ledger #${r.seq})`));
}

export async function erasureCreate(form: FormData) {
  const { lang } = await prefs();
  await go("/domains/d2/erasure", api("/v1/erasure", { method: "POST", body: JSON.stringify({ subject: String(form.get("subject") ?? ""), basis: String(form.get("basis") ?? ""), days: Number(form.get("days")) || 10 }) }),
    (r) => tr(lang, `삭제 요청 ${r.id} 등록 — 정보주체는 해시(${r.subjectHash.slice(0, 8)}…)만 기록`, `Erasure request ${r.id} created — data subject recorded as hash (${r.subjectHash.slice(0, 8)}…) only`));
}

export async function erasureStore(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("id"));
  await go(`/domains/d2/erasure?id=${encodeURIComponent(id)}`, api(`/v1/erasure/${id}/stores`, { method: "POST", body: JSON.stringify({ store: String(form.get("store")), status: String(form.get("status")), note: String(form.get("note") ?? "") }) }),
    () => tr(lang, `${form.get("store")} → ${form.get("status")} 기록`, `${form.get("store")} → ${form.get("status")} recorded`));
}

export async function erasureVerify(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("id"));
  await go(`/domains/d2/erasure?id=${encodeURIComponent(id)}`, api(`/v1/erasure/${id}:verify`, { method: "POST" }),
    (r) => r.verify.verdict === "block" ? tr(lang, `잔존 재검사 실패 — 사본 잔존 ${r.verify.residual.join(", ")} (재전파 필요, MSG-028)`, `Residual check failed — copies remain in ${r.verify.residual.join(", ")} (re-propagate, MSG-028)`)
      : tr(lang, `잔존 재검사 통과 (${r.verify.verdict}) — 삭제 증적 발행 가능`, `Residual check passed (${r.verify.verdict}) — receipt can be issued`));
}

export async function erasureCertify(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("id"));
  await go(`/domains/d2/erasure?id=${encodeURIComponent(id)}`, api(`/v1/erasure/${id}:certify`, { method: "POST" }),
    (r) => tr(lang, `삭제 증적 발행 — 원장 #${r.certified.seq} (해시 체인, 수정·삭제 불가)`, `Erasure receipt issued — ledger #${r.certified.seq} (hash chain, immutable)`));
}

export async function recallRun(_: R, form: FormData): Promise<R> {
  const outputs = String(form.get("outputs") ?? "").split(/\r?\n\s*-{3,}\s*\r?\n|(?:\r?\n\s*){2,}/).map((x) => x.trim()).filter(Boolean);
  const num = (k: string) => (String(form.get(k) ?? "").trim() ? Number(form.get(k)) : null);
  try {
    const r = await api("/v1/recall-tests", { method: "POST", body: JSON.stringify({ model: String(form.get("model")), version: String(form.get("version")), outputs,
      miaAuc: num("miaAuc"), dpEpsilon: num("dpEpsilon"), dedupRate: num("dedupRate") }) });
    revalidatePath("/domains/d2/erasure");
    return { ok: true, data: r };
  } catch (e) {
    return { ok: false, error: err(e) };
  }
}

export async function correctPoint(form: FormData) {
  const { lang } = await prefs();
  await go("/domains/d4/propagation", api("/v1/domains/d4/corrections", { method: "POST", body: JSON.stringify({ traceId: String(form.get("traceId")), status: String(form.get("status")), note: String(form.get("note") ?? "") }) }),
    (r) => tr(lang, `정정 상태 ${r.status} 기록 — 원장 #${r.seq}`, `Correction status ${r.status} recorded — ledger #${r.seq}`));
}

export async function retroCorrect(form: FormData) {
  const { lang } = await prefs();
  await go("/domains/d4/propagation", api("/v1/domains/d4/corrections", { method: "POST", body: JSON.stringify({ source: String(form.get("source")) }) }),
    (r) => tr(lang, `소급 정정 요청 ${r.requested}건 (완료·차단 ${r.skipped}건 제외)`, `Retroactive correction requested for ${r.requested} point(s) (${r.skipped} done/blocked skipped)`));
}

export async function driftScan() {
  const { lang } = await prefs();
  await go("/domains/d5/authz", api("/v1/domains/d5/authz:drift-scan", { method: "POST" }),
    (r) => tr(lang, `드리프트 점검 — 주체 ${r.principals} · ${r.verdict} · 발견 ${r.hits.length}건 (D5-07, 원장 기록)`, `Drift scan — ${r.principals} principals · ${r.verdict} · ${r.hits.length} findings (D5-07, ledgered)`));
}

export async function forceStop(form: FormData) {
  const { lang } = await prefs();
  const trace = String(form.get("trace"));
  await go(`/domains/d6/lineage/${encodeURIComponent(trace)}`, api(`/v1/rogue/${encodeURIComponent(String(form.get("name")))}:terminate`, { method: "POST", body: JSON.stringify({ reason: String(form.get("reason") || "실행 강제 종료") }) }),
    (r) => tr(lang, `강제 종료 ${r.name} — 격리 ${r.quarantine} · 토큰 회수 ${r.tokensRevoked} · 신원 폐기 ${r.identitiesRevoked.length}`, `Force-stopped ${r.name} — quarantine ${r.quarantine} · tokens revoked ${r.tokensRevoked} · identities revoked ${r.identitiesRevoked.length}`));
}

export async function scanOnce(_: R, form: FormData): Promise<R> {
  const { lang } = await prefs();
  let artifact: unknown;
  try {
    artifact = JSON.parse(String(form.get("artifact") || "{}"));
  } catch {
    return { ok: false, error: tr(lang, "JSON 파싱 오류", "JSON parse error") };
  }
  try {
    const r = await api("/v1/scan", { method: "POST", body: JSON.stringify({ artifact }) });
    revalidatePath(String(form.get("back") || "/"));
    return { ok: true, data: r };
  } catch (e) {
    return { ok: false, error: err(e) };
  }
}

export async function addTarget(form: FormData) {
  const { lang } = await prefs();
  const back = String(form.get("back") || "/scan");
  let artifact: any = {};
  try {
    artifact = JSON.parse(String(form.get("artifact") || "{}"));
  } catch { /* 아래 API 가 422 */ }
  await go(back.startsWith("/domains/") ? back : "/scan", api("/v1/scan-targets", { method: "POST", body: JSON.stringify({ name: String(artifact.name ?? artifact.kind ?? "target"), artifact, intervalSec: Number(form.get("interval")) || 21600 }) }),
    (r) => tr(lang, `주기 점검 대상 ${r.id} 등록 (${r.kind} · ${r.intervalSec}초)`, `Registered periodic target ${r.id} (${r.kind} · ${r.intervalSec}s)`));
}

export async function runTarget(form: FormData) {
  const { lang } = await prefs();
  const back = String(form.get("back") || "/scan");
  await go(back.startsWith("/domains/") ? back : "/scan", api(`/v1/scan-targets/${encodeURIComponent(String(form.get("id")))}:run`, { method: "POST" }),
    (r) => tr(lang, `점검 ${r.name ?? r.kind} → ${r.verdict}`, `Scanned ${r.name ?? r.kind} → ${r.verdict}`));
}

export async function decideSupply(form: FormData) {
  const { lang } = await prefs();
  const back = String(form.get("back") || "/");
  await go(back.startsWith("/domains/") ? back : "/", api("/v1/domains/decisions", { method: "POST", body: JSON.stringify({ kind: String(form.get("kind")), name: String(form.get("name")), decision: String(form.get("decision")), reason: String(form.get("reason") ?? "") }) }),
    (r) => r.approvalRef ? tr(lang, `${r.decision} — 2인 승인 요청 ${r.approvalRef}`, `${r.decision} — two-person approval requested ${r.approvalRef}`)
      : tr(lang, `${r.decision} 기록 — 원장 #${r.seq}${r.verdict ? ` · 재시험 ${r.verdict}` : ""}`, `${r.decision} recorded — ledger #${r.seq}${r.verdict ? ` · retest ${r.verdict}` : ""}`));
}
