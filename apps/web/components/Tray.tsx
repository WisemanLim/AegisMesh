"use client";
// SCR-B07 승인·작업 트레이 — 상단 바 '승인'에서 여는 우측 드로어. 만료 임박 순 승인 카드(빠른 승인·거절, 2인 진행, 신뢰 악용 경고)와 진행 작업.
import Link from "next/link";
import { useCallback, useEffect, useState, useTransition } from "react";
import { loadTray, quickDecide } from "@/app/approvals/tray-actions";
import { type Lang, sumL, tr, LX } from "@/lib/i18n";

const won = (n: number) => `₩${Math.round(n).toLocaleString("ko-KR")}`;
const mins = (iso?: string | null) => (iso ? Math.round((new Date(iso).getTime() - Date.now()) / 60000) : null);

export function Tray({ lang, pending, canApprove, label }: { lang: Lang; pending: number; canApprove: boolean; label: string }) {
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState<"approvals" | "jobs">("approvals");
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string>();
  const [form, setForm] = useState<{ id: string; decision: "approve" | "reject" } | null>(null);
  const [note, setNote] = useState<Record<string, string>>({});
  const [busy, start] = useTransition();
  const refresh = useCallback(() => start(async () => { const r = await loadTray(); r.ok ? (setData(r.data), setError(undefined)) : setError(r.error); }), []);
  useEffect(() => { if (open) refresh(); }, [open, refresh]);
  useEffect(() => {
    const k = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, []);
  const submit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!form) return;
    const reason = String(new FormData(e.currentTarget).get("reason") ?? "").trim();
    if (!reason) return;
    start(async () => {
      const r = await quickDecide(form.id, form.decision, reason);
      setNote((n) => ({ ...n, [form.id]: r.ok ? tr(lang, `${r.data.status} · 승인 ${r.data.approvals}/${r.data.required}`, `${r.data.status} · approvals ${r.data.approvals}/${r.data.required}`) : `✗ ${r.error}` }));
      setForm(null);
      const t = await loadTray();
      if (t.ok) setData(t.data);
    });
  };
  const items: any[] = data?.approvals ?? [];
  const jobs: any[] = data?.jobs ?? [];
  return (
    <>
      <button type="button" onClick={() => setOpen(true)} className="font-semibold" style={{ color: "var(--verdict-approval)" }} data-testid="tray-open" aria-haspopup="dialog">
        {label} {pending}
      </button>
      {open && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/20" onClick={() => setOpen(false)}>
          <aside role="dialog" aria-label={tr(lang, "승인·작업 트레이", "Approvals & jobs tray")} data-testid="tray" onClick={(e) => e.stopPropagation()}
            className="flex h-full w-[440px] flex-col border-l border-line bg-panel shadow-xl">
            <div className="flex items-center gap-2 border-b border-line p-3">
              <b>{tr(lang, "승인·작업 트레이", "Approvals & jobs")}</b>
              <button type="button" onClick={refresh} className="btn btn-secondary ml-auto h-6 text-xs" disabled={busy}>{busy ? "…" : "↻"}</button>
              <button type="button" onClick={() => setOpen(false)} className="btn btn-secondary h-6 text-xs" aria-label="close">✕</button>
            </div>
            <div role="tablist" className="flex gap-1 border-b border-line px-3 pt-2 text-sm">
              {(["approvals", "jobs"] as const).map((x) => (
                <button key={x} type="button" role="tab" aria-selected={tab === x} onClick={() => setTab(x)} data-testid={`tray-tab-${x}`}
                  className={`rounded-t px-3 py-1 ${tab === x ? "border border-b-0 border-line bg-panel font-semibold" : "text-muted"}`}>
                  {x === "approvals" ? tr(lang, `승인 대기 ${items.length}`, `Pending ${items.length}`) : tr(lang, `작업 ${jobs.length}`, `Jobs ${jobs.length}`)}
                </button>))}
            </div>
            <div className="flex-1 space-y-2 overflow-auto p-3 text-sm">
              {error && <p role="alert" className="text-xs text-red-600">{error}</p>}
              {!data && !error && <p className="text-xs text-muted">…</p>}
              {tab === "approvals" && data && (items.length === 0 ? <p className="text-xs text-muted">{tr(lang, "결정할 승인 요청 없음", "Nothing to decide")}</p> : items.map((a) => {
                const left = mins(a.expiresAt);
                const off = !canApprove || a.mine || a.decidedByMe;
                const why = !canApprove ? tr(lang, "승인자 역할 없음", "No approver role") : a.mine ? tr(lang, "본인 요청 (MSG-011)", "Your own request (MSG-011)") : a.decidedByMe ? tr(lang, "이미 결정함", "Already decided") : "";
                return (
                  <article key={a.id} className="rounded-lg border border-line p-3" style={{ borderLeft: "4px solid var(--verdict-approval)" }} data-testid="tray-card">
                    <div className="flex items-start gap-2">
                      <div className="flex-1">
                        <div className="font-semibold">{a.principal ?? a.requestedBy}{a.action?.type ? ` · ${a.action.type}` : a.tool ? ` · ${a.tool}` : ""}{a.action?.amount != null ? ` ${won(a.action.amount)}` : ""}</div>
                        <div className="text-xs text-muted">{sumL(lang, a.summary)}</div>
                      </div>
                      <span className="whitespace-nowrap text-xs" style={{ color: left != null && left < 30 ? "var(--verdict-block)" : undefined }}>
                        {left == null ? tr(lang, "만료 없음", "no expiry") : left > 0 ? tr(lang, `만료 ${left}분`, `${left} min left`) : tr(lang, "만료", "expired")}</span>
                    </div>
                    <div className="mt-1 flex flex-wrap gap-2 text-xs">
                      {a.action?.reversible === false && <span>{tr(lang, "되돌릴 수 없음", "irreversible")}</span>}
                      <span>{tr(lang, `${a.required}인 승인 ${a.approvals}/${a.required}`, `${a.approvals}/${a.required} approvals`)}</span>
                      <span className="text-muted">{a.gate}</span>
                    </div>
                    {a.repeats24h >= 3 && <div className="mt-1 rounded bg-[#fdf3e6] px-2 py-1 text-xs" style={{ color: "#9d6105" }} data-testid="tray-trust">
                      ⚠ {tr(lang, `X03 반복 요청 ${a.repeats24h}회/24h — 거절 권장`, `X03 repeated requests ${a.repeats24h}/24h — reject advised`)}</div>}
                    {note[a.id] && <div className="mt-1 text-xs font-semibold">{note[a.id]}</div>}
                    {form && form.id === a.id ? (
                      <form onSubmit={submit} className="mt-2 flex gap-1">
                        <input name="reason" required autoFocus className="input h-7 flex-1 text-xs" placeholder={tr(lang, "사유 (필수)", "Reason (required)")} aria-label="tray reason" />
                        <button className={`btn h-7 text-xs ${form.decision === "approve" ? "btn-primary" : "btn-danger"}`} disabled={busy}>{form.decision === "approve" ? tr(lang, "승인", "Approve") : tr(lang, "거절", "Reject")}</button>
                        <button type="button" className="btn btn-secondary h-7 text-xs" onClick={() => setForm(null)}>✕</button>
                      </form>
                    ) : (
                      <div className="mt-2 flex items-center gap-1" title={why || undefined}>
                        <button type="button" className="btn btn-primary h-7 text-xs" disabled={off} onClick={() => setForm({ id: a.id, decision: "approve" })}>{tr(lang, "승인", "Approve")}</button>
                        <button type="button" className="btn btn-danger h-7 text-xs" disabled={off} onClick={() => setForm({ id: a.id, decision: "reject" })}>{tr(lang, "거절", "Reject")}</button>
                        <Link className="ml-auto text-xs text-primary" href={`/approvals/${a.id}`} onClick={() => setOpen(false)}>{tr(lang, "상세 ›", "Details ›")}</Link>
                      </div>
                    )}
                  </article>
                );
              }))}
              {tab === "jobs" && data && (jobs.length === 0 ? <p className="text-xs text-muted">{tr(lang, "진행 중 작업 없음", "No jobs")}</p> : (
                <ul className="space-y-1 text-xs" data-testid="tray-jobs">{jobs.map((j) => (
                  <li key={j.seq} className="flex items-center gap-2 rounded border border-line px-2 py-1">
                    <b>{tr(lang, j.name, ({ "레드팀 캠페인": "Red-team campaign", "번들 반입": "Bundle import", "등록 심사": "Registration review", "포렌식 재현": "Forensic replay", "상시 점검": "Continuous scan", "골든셋 재생": "Golden-set replay", "코퍼스 평가": "Corpus evaluation" } as Record<string, string>)[j.name] ?? j.name)}</b>
                    <span className="text-muted">{LX(lang, j.detail)}</span><span className="ml-auto text-muted">{new Date(j.at).toLocaleTimeString(lang === "ko" ? "ko-KR" : "en-US")}</span><span>{j.status === "done" ? "✓" : "…"}</span>
                  </li>))}</ul>))}
            </div>
            <p className="border-t border-line p-3 text-[11px] text-muted">{tr(lang, "본인이 요청한 행동은 승인할 수 없음 · 사유 입력 필수 · 되돌릴 수 없는 행동은 두 번째 승인자 필요 (MSG-011)", "You cannot approve your own request · a reason is required · irreversible actions need a second approver (MSG-011)")}</p>
          </aside>
        </div>
      )}
    </>
  );
}
