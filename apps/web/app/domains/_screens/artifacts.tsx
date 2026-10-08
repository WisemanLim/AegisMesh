// 상시 점검 대상 보드 (D7·D8·D9 상세 화면 공통) — 등록 대상·최근 점검(근거)·격리·결정(2인은 승인함)·점검 패널.
import Link from "next/link";
import { Chip, VerdictBadge } from "@/components/Badges";
import { ScanPanel } from "@/components/ScanPanel";
import { api, safe } from "@/lib/api";
import { fmtTime, shortHash } from "@/lib/format";
import { type Lang, tr, LX } from "@/lib/i18n";
import { type Me, can } from "@/lib/session";
import { decideSupply, runTarget } from "../actions";

export type Board = { targets: any[]; scans: any[]; quarantine: any[]; pending: any[]; kinds: string[] };

export async function loadBoard(group: string): Promise<Board | null> {
  return (await safe(api(`/v1/domains/artifacts/${group}`), null as any)).data;
}

const DEC: Record<string, [string, string]> = {
  approve: ["승인", "Approve"], conditional: ["조건부 승인", "Conditional approve"], reject: ["반려", "Reject"], retest: ["재시험(지금 점검)", "Retest (scan now)"],
  "accept-change": ["변경 승인", "Accept change"], restore: ["직전 버전 복원", "Restore previous"], allow: ["허용 예외(2인)", "Allow exception (2-person)"],
  "pin-update": ["핀 갱신(2인)", "Update pin (2-person)"], release: ["격리 해제(2인)", "Release quarantine (2-person)"], "approve-sensitive": ["승인(쓰기·네트워크, 2인)", "Approve (write · network, 2-person)"],
};

export function decLabel(lang: Lang, d?: string) {
  return d ? tr(lang, ...(DEC[d] ?? [d, d])) : "—";
}

export function ArtifactBoard({ lang, user, x, back, decisions, title }: { lang: Lang; user: Me | null; x: Board; back: string; decisions: string[]; title?: string }) {
  const write = can(user, "scan");
  return (
    <div className="space-y-4">
      <section className="card overflow-hidden text-sm" data-testid="targets">
        <h2 className="p-3 font-semibold">{title ?? tr(lang, "점검 대상 · 결정", "Targets · decisions")} <span className="text-xs font-normal text-muted">({x.kinds.join(" · ")})</span></h2>
        <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "대상", "Target")}</th><th>{tr(lang, "종류", "Kind")}</th><th>{tr(lang, "주기", "Interval")}</th><th>{tr(lang, "최근 점검", "Last scan")}</th><th>{tr(lang, "결정", "Decision")}</th><th></th></tr></thead>
          <tbody>{x.targets.length === 0 ? <tr><td colSpan={6} className="text-muted">{tr(lang, "등록된 주기 점검 대상 없음 — 아래 점검 패널에서 등록", "No periodic targets — register from the scan panel below")}</td></tr> : x.targets.map((t) => (
            <tr key={t.id}><td className="mono">{t.name}</td><td>{t.kind}</td><td>{Math.round(t.intervalSec / 3600 * 10) / 10}h</td>
              <td>{t.lastVerdict ? <VerdictBadge v={t.lastVerdict} /> : "—"} <span className="text-muted">{fmtTime(t.lastRunAt)}</span></td>
              <td>{t.decision ? <span title={t.decision.reason}>{decLabel(lang, t.decision.decision)} · {t.decision.by}</span> : "—"}</td>
              <td>{write && <div className="flex flex-wrap gap-1">
                <form action={runTarget}><input type="hidden" name="id" value={t.id} /><input type="hidden" name="back" value={back} /><button className="btn btn-secondary h-6 text-xs">{tr(lang, "지금 점검", "Scan now")}</button></form>
                <form action={decideSupply} className="flex gap-1"><input type="hidden" name="kind" value={t.kind} /><input type="hidden" name="name" value={t.name} /><input type="hidden" name="back" value={back} />
                  <select name="decision" className="input h-6 text-xs" aria-label={`decision ${t.name}`}>{decisions.map((d) => <option key={d} value={d}>{decLabel(lang, d)}</option>)}</select>
                  <input name="reason" required className="input h-6 w-32 text-xs" placeholder={tr(lang, "사유", "Reason")} aria-label={`reason ${t.name}`} />
                  <button className="btn btn-primary h-6 text-xs">{tr(lang, "결정", "Decide")}</button></form></div>}</td></tr>))}</tbody></table>
      </section>
      <section className="card overflow-hidden text-sm" data-testid="scans">
        <h2 className="p-3 font-semibold">{tr(lang, "최근 점검 — 근거", "Recent scans — evidence")}</h2>
        <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "시각", "Time")}</th><th>{tr(lang, "대상", "Target")}</th><th>{tr(lang, "판정", "Verdict")}</th><th>{tr(lang, "근거 (규칙 · 위치 · 메모)", "Evidence (rule · location · note)")}</th><th>trace</th></tr></thead>
          <tbody>{x.scans.length === 0 ? <tr><td colSpan={5} className="text-muted">{tr(lang, "점검 기록 없음", "No scans yet")}</td></tr> : x.scans.slice(0, 25).map((r) => (
            <tr key={r.seq}><td>{fmtTime(r.at)}</td><td>{r.kind} · <span className="mono">{r.name ?? "—"}</span>{r.quarantine && <Chip>{tr(lang, "격리", "quarantined")}</Chip>}</td><td><VerdictBadge v={r.verdict} /></td>
              <td>{r.hits.length === 0 ? "—" : r.hits.map((h: any) => <div key={h.finding}><Link className="text-primary mono" href={`/findings/${h.finding}`}>{h.ruleId}</Link> {h.notes.map(([loc, n]: [string, string], i: number) => <span key={i} className="text-muted"> · {loc ? `${loc} ` : ""}{LX(lang, n)}</span>)}</div>)}</td>
              <td className="mono">{r.traceId ? <Link className="text-primary" href={`/findings?trace=${r.traceId}`}>{shortHash(r.traceId)}</Link> : "—"}</td></tr>))}</tbody></table>
      </section>
      {(x.quarantine.length > 0 || x.pending.length > 0) && (
        <section className="card space-y-1 p-4 text-sm" data-testid="quarantine">
          <h2 className="font-semibold">{tr(lang, "격리 · 승인 대기", "Quarantine · pending approvals")}</h2>
          <ul className="text-xs">{x.quarantine.map((q) => <li key={q.id}>⛔ {q.kind} <span className="mono">{q.value}</span> — <span data-user>{LX(lang, q.reason)}</span> · {fmtTime(q.at)}</li>)}
            {x.pending.map((a) => <li key={a.id}>⏳ <Link className="text-primary" href="/approvals">{a.id}</Link> · <span data-user>{LX(lang, a.summary)}</span></li>)}</ul>
        </section>
      )}
      <section className="card p-4 text-sm">
        <h2 className="mb-2 font-semibold">{tr(lang, "점검 패널 — 연동 도구 결과 넣기", "Scan panel — submit an integration's result")}</h2>
        <ScanPanel kinds={x.kinds} back={back} editable={write} />
      </section>
    </div>
  );
}
