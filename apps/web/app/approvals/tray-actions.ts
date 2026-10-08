"use server";
// SCR-B07 승인·작업 트레이 서버 액션 — 열 때 불러오고, 카드에서 바로 승인·거절(사유 필수).
import { revalidatePath } from "next/cache";
import { ApiError, api } from "@/lib/api";

const err = (e: unknown) => (e instanceof ApiError ? `${e.status}: ${typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail)}` : (e as Error).message);

export async function loadTray(): Promise<{ ok: boolean; data?: any; error?: string }> {
  try {
    return { ok: true, data: await api("/v1/approvals:tray") };
  } catch (e) {
    return { ok: false, error: err(e) };
  }
}

export async function quickDecide(id: string, decision: "approve" | "reject", reason: string): Promise<{ ok: boolean; data?: any; error?: string }> {
  try {
    const r = await api(`/v1/approvals/${encodeURIComponent(id)}:decide`, { method: "POST", body: JSON.stringify({ decision, reason }) });
    revalidatePath("/", "layout");
    return { ok: true, data: { status: r.status, approvals: r.decisions.filter((d: any) => d.decision === "approve").length, required: r.required } };
  } catch (e) {
    return { ok: false, error: err(e) };
  }
}
