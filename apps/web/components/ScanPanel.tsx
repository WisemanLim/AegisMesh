"use client";
// 상시 점검 패널 — 점검 대상(artifact JSON)을 붙여 넣어 바로 점검(판정·원장)하거나 주기 점검 대상으로 등록한다.
import { useActionState, useState } from "react";
import { addTarget, scanOnce } from "@/app/domains/actions";
import { tr } from "@/lib/i18n";
import { useLang } from "@/lib/lang";
import { PRESETS } from "@/lib/artifactPresets";

const V: Record<string, string> = { allow: "#257a6e", alert: "#9d6105", transform: "#3b6fd8", require_approval: "#8a4fd8", block: "#c03333" };

export function ScanPanel({ kinds, back, editable }: { kinds: string[]; back: string; editable: boolean }) {
  const lang = useLang();
  const [kind, setKind] = useState(kinds[0]);
  const [text, setText] = useState(JSON.stringify(PRESETS[kinds[0]] ?? { kind: kinds[0] }, null, 1));
  const [s, action, pending] = useActionState(scanOnce, null);
  const r = s?.ok ? s.data : null;
  return (
    <div className="space-y-2 text-sm" data-testid="scan-panel">
      <div className="flex flex-wrap items-center gap-2">
        <select className="input h-8 text-xs" value={kind} aria-label="kind" onChange={(e) => { setKind(e.target.value); setText(JSON.stringify(PRESETS[e.target.value] ?? { kind: e.target.value }, null, 1)); }}>
          {kinds.map((k) => <option key={k}>{k}</option>)}
        </select>
        <span className="text-xs text-muted">{tr(lang, "견본 = 연동 도구 결과 모양. 값을 바꿔 시험", "Sample = the shape of an integration's output. Edit to test")}</span>
      </div>
      <form className="space-y-2">
        <textarea name="artifact" className="input mono h-36 w-full text-xs" value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} aria-label="artifact" />
        <input type="hidden" name="back" value={back} />
        {editable ? (
          <div className="flex flex-wrap items-center gap-2">
            <button formAction={action} className="btn btn-primary text-xs" disabled={pending} data-testid="scan-once">{tr(lang, "지금 점검 (판정·원장)", "Scan now (verdict · ledger)")}</button>
            <input name="interval" className="input h-8 w-24 text-xs" defaultValue="21600" aria-label="interval" />
            <button formAction={addTarget} className="btn btn-secondary text-xs" data-testid="scan-register">{tr(lang, "주기 점검 대상 등록(초)", "Register for periodic scan (s)")}</button>
          </div>
        ) : <p className="text-xs text-muted">{tr(lang, "점검 권한 필요", "Scan permission required")}</p>}
      </form>
      {s && !s.ok && <p role="alert" className="text-xs text-red-600">{s.error}</p>}
      {r && (
        <div className="rounded border border-line p-2 text-xs" data-testid="scan-result">
          <b style={{ color: V[r.verdict] }}>{r.verdict}</b> · {r.kind} {r.name ?? ""} · {r.latencyMs}ms{r.quarantine && ` · ${tr(lang, "격리", "quarantined")} ${r.quarantine}`}{r.incidents?.length ? ` · ${tr(lang, "사건", "incident")} ${r.incidents.join(", ")}` : ""}
          <ul>{r.findings.filter((f: any) => f.verdict !== "allow").map((f: any) => <li key={f.id}><span className="mono">{f.ruleId}</span> {f.confidence} — {f.evidence.map((e: any) => e.note).join("; ")}</li>)}</ul>
        </div>
      )}
    </div>
  );
}
