"use client";
import { startTransition, useActionState, useState } from "react";
import { labelSample, runPreview, testAgent } from "@/app/instant/preview-actions";

import { L, LX } from "@/lib/i18n";
import { useLang } from "@/lib/lang";

const V: Record<string, string> = { allow: "#257a6e", alert: "#9d6105", transform: "#3b6fd8", require_approval: "#8a4fd8", block: "#c03333" };
const submit = (action: (f: FormData) => void) => (e: React.FormEvent<HTMLFormElement>) => { e.preventDefault(); const fd = new FormData(e.currentTarget); startTransition(() => action(fd)); };

export function Previewer({ profiles, initial = "tool-agent", target, traffic }: { profiles: { id: string; nameKo: string }[]; initial?: string; target?: string;
  traffic?: { enabled: boolean; total: number } }) {
  const lang = useLang();
  const [s, action, pending] = useActionState(runPreview, null);
  const [labels, setLabels] = useState<Record<string, string | null>>({});
  const r = s?.ok ? s.data : null;
  const mark = (id: string, l: "benign" | "attack") => startTransition(async () => { const x = await labelSample(id, l); if (x?.ok) setLabels((m) => ({ ...m, [id]: l })); });
  return (
    <div className="grid grid-cols-[360px_1fr] gap-4">
      <form onSubmit={submit(action)} className="card space-y-2 p-4 text-sm">
        <label className="block">{L(lang, "프로파일")}<select name="profile" className="input mt-1 w-full" defaultValue={initial}>{profiles.map((p) => <option key={p.id} value={p.id}>{lang === "en" ? p.id : p.nameKo} ({p.id})</option>)}</select></label>
        <label className="block">{L(lang, "적용 단계")}<select name="stage" className="input mt-1 w-full" defaultValue="enforce"><option value="observe">{L(lang, "관측만")}</option><option value="partial">{L(lang, "부분 차단")}</option><option value="enforce">{L(lang, "전체 차단")}</option></select></label>
        <fieldset className="text-xs" data-testid="preview-source"><legend className="mb-1">{lang === "en" ? "Samples" : "표본"}</legend>
          <label className="mr-3"><input type="radio" name="source" value="corpus" defaultChecked={!traffic?.enabled} /> {lang === "en" ? "Test corpus / pasted" : "시험 코퍼스·붙여 넣기"}</label>
          <label><input type="radio" name="source" value="traffic" defaultChecked={!!traffic?.enabled} disabled={!traffic?.enabled} /> {lang === "en" ? `Real traffic, masked (${traffic?.total ?? 0})` : `실제 트래픽·마스킹 (${traffic?.total ?? 0}건)`}</label>
          {!traffic?.enabled && <div className="mt-1 text-muted">{lang === "en" ? "Off by default (NFR-D1) — turn on in Data protection (two approvals)" : "기본 미보존(NFR-D1) — 데이터 보호에서 켠다(2인 승인)"} · <a className="text-primary" href="/admin/data-protection">→</a></div>}
          <input type="hidden" name="target" value={target ?? ""} />
        </fieldset>
        <label className="block">{L(lang, "표본 JSONL (선택)")}<textarea name="samples" className="input mono mt-1 h-32 w-full text-xs" placeholder='{"gate":"output","label":"attack","request":{"output":"…"}}' /></label>
        <button className="btn btn-primary w-full justify-center" disabled={pending}>{L(lang, "재생 (차단·기록 없음)")}</button>
        <p className="text-xs text-muted">{L(lang, "원문 미보존(NFR-D1) — 표본을 비우면 바인딩 에이전트의 정상·공격 시험 코퍼스로 재생한다.")}</p>
      </form>
      <div className="space-y-3 text-sm" data-testid="preview-result">
        {s && !s.ok && <p role="alert" className="text-red-600">{LX(lang, s.error)}</p>}
        {r && (<>
          <div className="card grid grid-cols-5 gap-2 p-3 text-center">
            {Object.entries(r.counts).map(([v, n]: [string, any]) => <div key={v}><div className="text-xs" style={{ color: V[v] }}>{v}</div><b className="text-lg">{n}</b></div>)}
          </div>
          <div className="card p-3 text-xs">{L(lang, "표본 ")}{LX(lang, r.samples)}{L(lang, " · 오탐 추정 ")}{r.estimate.falsePositiveRate == null ? "—" : `${(r.estimate.falsePositiveRate * 100).toFixed(1)}%`}{L(lang, " (정상 ")}{LX(lang, r.estimate.benign)}{L(lang, ") · 미탐 추정 ")}{r.estimate.missRate == null ? "—" : `${(r.estimate.missRate * 100).toFixed(1)}%`}{L(lang, " (공격 ")}{LX(lang, r.estimate.attack)}{L(lang, ") · 지연 ")}{Object.entries(r.latency).map(([g, x]: [string, any]) => `${g} p95 ${x.p95Ms}/${x.budgetMs}ms`).join(" · ")}</div>
          {r.traffic && <div className="card p-3 text-xs" data-testid="traffic-summary">{lang === "en"
            ? `Real traffic ${r.traffic.total} · would block ${r.traffic.wouldBlock} · newly blocked ${r.traffic.newlyBlocked} (review for false positives) · unblocked ${r.traffic.unblocked} · labelled ${r.traffic.labeled}`
            : `실제 트래픽 ${r.traffic.total}건 · 차단 예상 ${r.traffic.wouldBlock} · 새로 차단 ${r.traffic.newlyBlocked}(오탐 검토 대상) · 차단 해제 ${r.traffic.unblocked} · 라벨 ${r.traffic.labeled}`}</div>}
          <div className="card p-3 text-xs"><b>{L(lang, "에이전트 기여")}</b> {r.contribution.map((c: any) => `${c.agent} ${c.nonAllow}`).join(" · ")}</div>
          <table className="grid-table text-xs"><thead><tr><th>{L(lang, "관문")}</th><th>{L(lang, "라벨")}</th><th>{L(lang, "출처")}</th><th>{L(lang, "표본")}</th>{r.traffic && <th>{lang === "en" ? "Original" : "원래 판정"}</th>}<th>{L(lang, "판정")}</th><th>{L(lang, "규칙")}</th></tr></thead>
            <tbody>{r.items.slice(0, 40).map((x: any, i: number) => {
              const lab = x.name in labels ? labels[x.name] : x.label;
              return (
              <tr key={i} data-sample={x.source === "traffic" ? x.name : undefined}><td>{LX(lang, x.gate)}</td>
                <td>{x.source === "traffic" ? <span className="flex gap-1">
                  {(["benign", "attack"] as const).map((l) => <button key={l} type="button" onClick={() => mark(x.name, l)} data-label={l}
                    className={`rounded border px-1 ${lab === l ? "border-primary bg-primary-soft text-primary" : "border-line"}`}>{l === "benign" ? (lang === "en" ? "benign" : "정상") : (lang === "en" ? "attack" : "공격")}</button>)}</span> : LX(lang, x.label)}</td>
                <td>{LX(lang, x.source)}</td><td className="mono max-w-[220px] truncate" title={x.name}>{LX(lang, x.name)}</td>
                {r.traffic && <td>{x.original ? <b style={{ color: V[x.original] }}>{x.original}</b> : "—"}</td>}
                <td><b style={{ color: V[x.verdict] }}>{LX(lang, x.verdict)}</b></td><td className="mono">{x.rules.join(", ")}</td></tr>
              );
            })}</tbody></table>
        </>)}
      </div>
    </div>
  );
}

export function AgentTester({ agent, gate, sample }: { agent: string; gate: string; sample: string }) {
  const lang = useLang();
  const [s, action, pending] = useActionState(testAgent, null);
  const r = s?.ok ? s.data : null;
  return (
    <form onSubmit={submit(action)} className="space-y-2 text-sm">
      <input type="hidden" name="agent" value={agent} /><input type="hidden" name="gate" value={gate} />
      <textarea name="request" defaultValue={sample} spellCheck={false} className="input mono h-28 w-full text-xs" aria-label="test request" />
      <button className="btn btn-primary" disabled={pending}>{L(lang, "시험 (차단·기록 없음)")}</button>
      {s && !s.ok && <p role="alert" className="text-xs text-red-600">{LX(lang, s.error)}</p>}
      {r && (
        <div className="card p-3 text-xs" data-testid="agent-test">
          <b style={{ color: V[r.deployed.verdict] }}>{LX(lang, r.deployed.verdict)}</b> · {r.deployed.decisions.map((d: any) => `${d.ruleId} (${d.original}→${d.effective})`).join(" · ")}
          {r.transformed && <div className="mono mt-1">{L(lang, "변환: ")}{String(r.transformed.value).slice(0, 200)}</div>}
          {r.findings[0]?.evidence?.map((e: any, i: number) => <div key={i} className="text-muted">{L(lang, "근거: ")}{LX(lang, e.kind)} — {LX(lang, e.note)}</div>)}
        </div>
      )}
    </form>
  );
}
