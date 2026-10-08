"use server";
// 공정성·윤리 지표(SCR-N06) · 시스템·모델 카드(SCR-N07) 서버 액션.
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { ApiError, api } from "@/lib/api";
import { tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";

const err = (e: unknown) => (e instanceof ApiError ? `${e.status}: ${typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail)}` : (e as Error).message);

function back(path: string, form: FormData, msg: string, keep: string[]): never {
  const q = new URLSearchParams();
  for (const k of keep) if (form.get(k)) q.set(k, String(form.get(k)));
  q.set("msg", msg);
  revalidatePath("/", "layout");
  redirect(`${path}?${q}`);
}

export async function measureNow(form: FormData) {
  const { lang } = await prefs();
  const target = String(form.get("target") || "") || null;
  let msg: string;
  try {
    const r = await api("/v1/compliance/fairness:measure", { method: "POST", body: JSON.stringify({ target, days: Number(form.get("days") || 7) }) });
    const over = Object.entries(r.over as Record<string, any>).map(([ax, v]) => `${ax} ${v.gapPp.toFixed(2)}%p`).join(", ");
    msg = over ? tr(lang, `측정 완료 — 한도 초과 ${over} · 경보 · 위험 ${r.risk} 등록 (MSG-023)`, `Measured — over the limit ${over} · alert · risk ${r.risk} registered (MSG-023)`)
      : tr(lang, `측정 완료 — 판정 ${r.records}건 · ${r.verdict}`, `Measured — ${r.records} records · ${r.verdict}`);
  } catch (e) {
    msg = tr(lang, `실패 ${err(e)}`, `Failed ${err(e)}`);
  }
  back("/compliance/fairness", form, msg, ["target", "days"]);
}

export async function saveAssessment(form: FormData) {
  const { lang } = await prefs();
  let msg: string;
  try {
    await api("/v1/compliance/fairness/assessments", { method: "POST", body: JSON.stringify({ target: String(form.get("assessTarget")), summary: String(form.get("summary") ?? ""), status: String(form.get("status") || "approved") }) });
    msg = tr(lang, `영향 평가 기록 — ${form.get("assessTarget")}`, `Impact assessment recorded — ${form.get("assessTarget")}`);
  } catch (e) {
    msg = tr(lang, `실패 ${err(e)}`, `Failed ${err(e)}`);
  }
  back("/compliance/fairness", form, msg, ["target", "days"]);
}

export async function saveDisclosure(form: FormData) {
  const { lang } = await prefs();
  let msg: string;
  try {
    const r = await api("/v1/compliance/fairness/disclosure", { method: "PUT", body: JSON.stringify({ internal: form.get("internal") === "on", external: form.get("external") === "on" }) });
    msg = tr(lang, `공개 설정 — 내부 ${r.internal ? "공개" : "비공개"} · 외부 ${r.external ? "공개" : "비공개"}`, `Disclosure — internal ${r.internal ? "on" : "off"} · external ${r.external ? "on" : "off"}`);
  } catch (e) {
    msg = tr(lang, `실패 ${err(e)}`, `Failed ${err(e)}`);
  }
  back("/compliance/fairness", form, msg, ["target", "days"]);
}

export async function generateCards(form: FormData) {
  const { lang } = await prefs();
  let msg: string;
  try {
    const r = await api("/v1/compliance/cards:generate", { method: "POST", body: JSON.stringify({ subject: String(form.get("subject") || "") || null }) });
    const made = r.items.filter((x: any) => x.created);
    msg = made.length ? tr(lang, `새 판 ${made.length}건 — ${made.map((x: any) => `${x.subject} v${x.version}`).join(", ")}`, `${made.length} new versions — ${made.map((x: any) => `${x.subject} v${x.version}`).join(", ")}`)
      : tr(lang, "변경 없음 — 모든 카드 최신 지문", "No changes — every card matches its inputs");
  } catch (e) {
    msg = tr(lang, `실패 ${err(e)}`, `Failed ${err(e)}`);
  }
  back("/compliance/cards", form, msg, ["s"]);
}

export async function publishCard(form: FormData) {
  const { lang } = await prefs();
  const s = String(form.get("s"));
  let msg: string;
  try {
    const r = await api(`/v1/compliance/cards/${encodeURIComponent(s)}:publish`, { method: "POST", body: JSON.stringify({ audiences: form.getAll("audiences").map(String) }) });
    msg = tr(lang, `검토 요청 ${r.approvalRef} — 승인 후 공개 (${r.audiences.join(", ")})`, `Review requested ${r.approvalRef} — published after approval (${r.audiences.join(", ")})`);
  } catch (e) {
    msg = tr(lang, `실패 ${err(e)}`, `Failed ${err(e)}`);
  }
  back("/compliance/cards", form, msg, ["s"]);
}
