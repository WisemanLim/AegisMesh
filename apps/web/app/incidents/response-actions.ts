"use server";
// SCR-O07 사고 대응 런북 서버 액션 — 단계 실행(고위험은 승인 경유)·포렌식 보존·L3 재현.
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { ApiError, api } from "@/lib/api";
import { tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";

const err = (e: unknown) => (e instanceof ApiError ? `${e.status}: ${typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail)}` : (e as Error).message);

function done(id: string, msg: string): never {
  revalidatePath("/", "layout");
  redirect(`/incidents/${encodeURIComponent(id)}/response?msg=${encodeURIComponent(msg)}`);
}

export async function runStep(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("id")), step = String(form.get("step"));
  let msg: string;
  try {
    const r = await api(`/v1/incidents/${encodeURIComponent(id)}/steps`, { method: "POST", body: JSON.stringify({ step, note: String(form.get("note") ?? "") }) });
    msg = r.pending ? tr(lang, `${step}: 승인 필요 — 요청 ${r.approvalRef} (2인 승인 후 자동 실행)`, `${step}: needs approval — request ${r.approvalRef} (runs after two approvals)`)
      : r.reassessed ? tr(lang, `${step}: 재평가 ${r.reassessed.total}건 · 변화 ${r.reassessed.changed.length}건`, `${step}: re-assessed ${r.reassessed.total} · changed ${r.reassessed.changed.length}`)
      : r.quarantined ? tr(lang, `${step}: 격리 ${r.quarantined.length}건`, `${step}: quarantined ${r.quarantined.length}`)
      : r.released ? tr(lang, `${step}: 격리 해제 ${r.released.length}건`, `${step}: released ${r.released.length}`)
      : r.policy ? tr(lang, `${step}: 정책 ${r.policy} 확인`, `${step}: policy ${r.policy} confirmed`)
      : tr(lang, `${step}: 완료 (원장 #${r.seq})`, `${step}: done (ledger #${r.seq})`);
  } catch (e) {
    msg = tr(lang, `실패 ${err(e)}`, `Failed ${err(e)}`);
  }
  done(id, msg);
}

export async function preserve(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("id"));
  let msg: string;
  try {
    const r = await api(`/v1/incidents/${encodeURIComponent(id)}:preserve`, { method: "POST" });
    msg = tr(lang, `포렌식 보존 — 판정 ${r.findings} · 기록 ${r.records} · 다이제스트 ${r.digest.slice(0, 12)}… · 법적 보존 ON`, `Preserved — ${r.findings} findings · ${r.records} records · digest ${r.digest.slice(0, 12)}… · legal hold ON`);
  } catch (e) {
    msg = tr(lang, `실패 ${err(e)}`, `Failed ${err(e)}`);
  }
  done(id, msg);
}

export async function replay(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("id"));
  let msg: string;
  try {
    const r = await api(`/v1/incidents/${encodeURIComponent(id)}:replay`, { method: "POST" });
    msg = tr(lang, `재현 ${r.matched}/${r.total} 일치 · ${r.isolation}`, `Replay ${r.matched}/${r.total} matched · ${String(r.isolation).startsWith("L0") ? "L0 (no L3 runtime — replayed in-process)" : r.isolation}`);
  } catch (e) {
    msg = tr(lang, `실패 ${err(e)}`, `Failed ${err(e)}`);
  }
  done(id, msg);
}
