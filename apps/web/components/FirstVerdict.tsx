"use client";
import { startTransition, useActionState } from "react";
import { firstVerdict } from "@/app/setup/actions";

import { L, LX } from "@/lib/i18n";
import { useLang } from "@/lib/lang";

const PROFILES = [["minimal-visibility", "최소 가시성 — 관측만, 요청 경로 영향 없음 (기본)"], ["chatbot-baseline", "챗봇 기본"], ["tool-agent", "도구 호출 에이전트"], ["regulated-kr", "국내 규제"]];
const V: Record<string, string> = { allow: "#257a6e", alert: "#9d6105", transform: "#3b6fd8", require_approval: "#8a4fd8", block: "#c03333" };

export function FirstVerdict() {
  const lang = useLang();
  const [s, action, pending] = useActionState(firstVerdict, null);
  const r = s?.ok ? s.data : null;
  const hits = r ? r.findings.filter((f: any) => f.verdict !== "allow") : [];
  const eff: Record<string, string> = r ? Object.fromEntries(r.decisions.filter((d: any) => d.findingId).map((d: any) => [d.findingId, d.effective])) : {};
  return (
    <div className="grid grid-cols-[380px_1fr] gap-4">
      <form onSubmit={(e) => { e.preventDefault(); const fd = new FormData(e.currentTarget); startTransition(() => action(fd)); }} className="card space-y-2 p-4 text-sm">
        <label className="block">{L(lang, "① 보호 대상 이름")}<input name="target" defaultValue="chat.first-service" className="input mt-1 w-full" /></label>
        <fieldset className="space-y-1"><legend>{L(lang, "② 프로파일")}</legend>{PROFILES.map(([id, ko], i) => { const l = L(lang, ko); return (
          <label key={id} className="flex items-center gap-2 text-xs"><input type="radio" name="profile" value={id} defaultChecked={i === 0} />{l}</label>); })}</fieldset>
        <label className="block">{L(lang, "③ 시험 표본")}<select name="sample" className="input mt-1 w-full" defaultValue="injection">
          <option value="injection">{L(lang, "입력 — 지시 주입")}</option><option value="leak">{L(lang, "출력 — 자격증명 유출")}</option><option value="tool">{L(lang, "도구 — 고위험 이체")}</option></select></label>
        <button className="btn btn-primary w-full justify-center" disabled={pending}>{L(lang, "④ 시험 요청 보내기")}</button>
      </form>
      <div className="text-sm" data-testid="first-verdict">
        {s && !s.ok && <p role="alert" className="text-red-600">{LX(lang, s.error)}</p>}
        {r && (
          <div className="card space-y-2 p-4">
            <div className="text-lg">{L(lang, "첫 판정 ")}<b style={{ color: V[r.verdict] }}>{LX(lang, r.verdict)}</b> <span className="text-xs text-muted">{LX(lang, r.gate)}{L(lang, " · 단계 ")}{LX(lang, r.stage)}{L(lang, " · 프로파일 에이전트 {0}종 중 {1}종 실행 · ", r.agentCount, r.agents.length)}{LX(lang, r.latencyMs)}ms / {LX(lang, r.budgetMs)}ms</span></div>
            {hits.length === 0 ? <p className="text-xs">{L(lang, "위험 없음 — 실행한 에이전트 ")}{r.agents.join(", ")}{L(lang, " 모두 allow. 다른 표본이나 프로파일로 다시 시험할 수 있다.")}</p> : (
              <table className="grid-table text-xs"><thead><tr><th>{L(lang, "에이전트")}</th><th>{L(lang, "규칙")}</th><th>{L(lang, "원판정")}</th><th>{L(lang, "유효")}</th><th>{L(lang, "근거")}</th></tr></thead>
                <tbody>{hits.slice(0, 8).map((f: any) => (
                  <tr key={f.id}><td>{f.agent.id}</td><td className="mono">{LX(lang, f.ruleId)}</td><td>{LX(lang, f.verdict)}</td><td style={{ color: V[eff[f.id]] }}>{LX(lang, eff[f.id])}</td><td>{f.evidence.map((e: any) => e.note).join("; ")}</td></tr>))}</tbody></table>)}
            <p className="text-xs text-muted">trace {LX(lang, r.traceId)}{L(lang, " · 원장에 기록됨. 관측만(observe) 단계는 차단하지 않고 경보로 남긴다.")}</p>
          </div>
        )}
      </div>
    </div>
  );
}
