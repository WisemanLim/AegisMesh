"use client";
// 에이전트 설정 편집기 — 정책 agentParams (도메인 상세 화면 공통). 변경 시험(단위 시험·코퍼스 영향·표본 판정) 후 사유와 함께 배포.
// 관문에서는 정책 값이 요청 값보다 우선한다. 비워 두면 그 키는 정책에서 빠지고 엔진 기본값이 쓰인다.
import { useRouter } from "next/navigation";
import { startTransition, useActionState, useEffect, useMemo, useState } from "react";
import { saveAgentConfig, testAgentConfig } from "@/app/policies/actions";
import { tr } from "@/lib/i18n";
import { useLang } from "@/lib/lang";

type Param = { type: string; items?: string; default?: unknown; min?: number; max?: number; enum?: unknown[]; labelKo: string; labelEn: string };
export type AgentConfig = { agent: string; item?: string; policy: string; principal?: string | null; schema: Record<string, Param>; values: Record<string, unknown>; relocated: boolean; rule: string;
  rules?: Record<string, string>; rulesEn?: Record<string, string>; verdicts?: string[]; overrides?: Record<string, { verdict?: string; threshold?: number }>; minConfidence?: number };
type Ov = Record<string, { verdict: string; threshold: string }>;

const V: Record<string, string> = { allow: "#257a6e", alert: "#9d6105", transform: "#3b6fd8", require_approval: "#8a4fd8", block: "#c03333" };

function toText(p: Param, v: unknown): string {
  if (v === undefined || v === null) return "";
  if (p.type === "list") return (v as unknown[]).join("\n");
  if (p.type === "map" || p.type === "json") return JSON.stringify(v, null, 1);
  return String(v);
}

function parse(p: Param, s: string): { v?: unknown; err?: string } {
  const t = s.trim();
  if (!t) return {};
  if (p.type === "list") {
    const xs = t.split(/\n|,/).map((x) => x.trim()).filter(Boolean);
    if (p.items === "integer" || p.items === "number") {
      const ns = xs.map(Number);
      return ns.some((n) => Number.isNaN(n)) ? { err: "number" } : { v: ns };
    }
    return { v: xs };
  }
  if (p.type === "number" || p.type === "integer") {
    const n = Number(t);
    if (Number.isNaN(n) || (p.type === "integer" && !Number.isInteger(n))) return { err: p.type };
    if ((p.min != null && n < p.min) || (p.max != null && n > p.max)) return { err: `${p.min ?? "-∞"}…${p.max ?? "∞"}` };
    return { v: n };
  }
  if (p.type === "boolean") return { v: t === "true" };
  if (p.type === "map" || p.type === "json") {
    try {
      return { v: JSON.parse(t) };
    } catch {
      return { err: "JSON" };
    }
  }
  return { v: t };
}

function Field({ k, p, text, set, err, current, editable }: { k: string; p: Param; text: string; set: (s: string) => void; err?: string; current: boolean; editable: boolean }) {
  const lang = useLang();
  const def = p.default === undefined ? tr(lang, "엔진 기본값", "engine default") : toText(p, p.default).replace(/\n/g, ", ") || "[]";
  const multi = p.type === "list" || p.type === "map" || p.type === "json";
  const cls = `input mono mt-1 w-full text-xs ${err ? "border-red-500" : ""}`;
  return (
    <label className="block text-xs" data-testid={`cfg-${k}`}>
      <span className="font-semibold">{tr(lang, p.labelKo, p.labelEn)}</span> <span className="mono text-muted">{k}</span>
      {current ? <span className="ml-1 rounded bg-primary-soft px-1 text-primary">{tr(lang, "정책 값", "policy")}</span> : <span className="ml-1 text-muted">{tr(lang, `기본: ${def}`, `default: ${def}`)}</span>}
      {p.type === "boolean" ? (
        <select className={cls} value={text} onChange={(e) => set(e.target.value)} disabled={!editable}>
          <option value="">{tr(lang, "미설정 (기본값)", "unset (default)")}</option><option value="true">true</option><option value="false">false</option>
        </select>
      ) : p.enum ? (
        <select className={cls} value={text} onChange={(e) => set(e.target.value)} disabled={!editable}>
          <option value="">{tr(lang, "미설정 (기본값)", "unset (default)")}</option>{p.enum.map((x) => <option key={String(x)}>{String(x)}</option>)}
        </select>
      ) : multi ? (
        <textarea className={`${cls} h-20`} value={text} onChange={(e) => set(e.target.value)} readOnly={!editable} spellCheck={false}
          placeholder={p.type === "list" ? tr(lang, "한 줄에 하나", "one per line") : "{ }"} />
      ) : (
        <input className={cls} value={text} onChange={(e) => set(e.target.value)} readOnly={!editable} inputMode={p.type === "string" ? undefined : "decimal"} />
      )}
      {err && <span role="alert" className="text-red-600">{tr(lang, `형식 오류: ${err}`, `invalid: ${err}`)}</span>}
    </label>
  );
}

function RuleTable({ cfg, ov, set, editable }: { cfg: AgentConfig; ov: Ov; set: (o: Ov) => void; editable: boolean }) {
  const lang = useLang();
  const rules = Object.entries(cfg.rules ?? {}).filter(([k]) => !k.endsWith(".pass"));
  return (
    <table className="grid-table text-xs" data-testid="rule-overrides">
      <thead><tr><th>{tr(lang, "규칙", "Rule")}</th><th>{tr(lang, "설명", "Description")}</th><th>{tr(lang, "조치 재정의", "Action override")}</th><th>{tr(lang, "임계(미만 → 경보)", "Threshold (below → alert)")}</th></tr></thead>
      <tbody>{rules.map(([k, d]) => (
        <tr key={k}><td className="mono">{k}</td><td>{(lang === "en" && cfg.rulesEn?.[k]) || d}</td>
          <td><select className="input h-7 text-xs" value={ov[k]?.verdict ?? ""} disabled={!editable} aria-label={`verdict ${k}`}
            onChange={(e) => set({ ...ov, [k]: { verdict: e.target.value, threshold: ov[k]?.threshold ?? "" } })}>
            <option value="">{tr(lang, "기본", "default")}</option>{(cfg.verdicts ?? []).map((v) => <option key={v}>{v}</option>)}</select></td>
          <td><input className="input h-7 w-20 text-xs" value={ov[k]?.threshold ?? ""} readOnly={!editable} inputMode="decimal" aria-label={`threshold ${k}`}
            placeholder={String(cfg.minConfidence ?? "")} onChange={(e) => set({ ...ov, [k]: { verdict: ov[k]?.verdict ?? "", threshold: e.target.value } })} /></td></tr>
      ))}</tbody>
    </table>
  );
}

export function AgentSettings({ cfg, editable, sample, showRules = false }: { cfg: AgentConfig; editable: boolean; sample?: object; showRules?: boolean }) {
  const lang = useLang();
  const router = useRouter();
  const keys = Object.keys(cfg.schema);
  const [ov, setOv] = useState<Ov>(() => Object.fromEntries(Object.entries(cfg.overrides ?? {}).map(([k, v]) => [k, { verdict: v.verdict ?? "", threshold: v.threshold == null ? "" : String(v.threshold) }])));
  const ovOut = showRules ? JSON.stringify(Object.fromEntries(Object.entries(ov).filter(([, v]) => v.verdict || v.threshold.trim())
    .map(([k, v]) => [k, { verdict: v.verdict || null, threshold: v.threshold.trim() ? Number(v.threshold) : null }]))) : "";
  const badOv = Object.values(ov).some((v) => v.threshold.trim() && (Number.isNaN(Number(v.threshold)) || Number(v.threshold) < 0 || Number(v.threshold) > 1));
  const [texts, setTexts] = useState<Record<string, string>>(() => Object.fromEntries(keys.map((k) => [k, toText(cfg.schema[k], cfg.values[k])])));
  const [reason, setReason] = useState("");
  const [smp, setSmp] = useState(sample ? JSON.stringify(sample, null, 1) : "");
  const [t, testAction, testing] = useActionState(testAgentConfig, null);
  const [d, saveAction, saving] = useActionState(saveAgentConfig, null);
  const parsed = useMemo(() => Object.fromEntries(keys.map((k) => [k, parse(cfg.schema[k], texts[k] ?? "")])), [texts]); // eslint-disable-line react-hooks/exhaustive-deps
  const errors = Object.entries(parsed).filter(([, x]) => x.err);
  const values = JSON.stringify(Object.fromEntries(Object.entries(parsed).filter(([, x]) => x.v !== undefined).map(([k, x]) => [k, x.v]))) + ovOut;
  const [tested, setTested] = useState<string | null>(null);
  useEffect(() => { if (t?.ok) setTested(values); }, [t]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (d?.ok) router.refresh(); }, [d]); // eslint-disable-line react-hooks/exhaustive-deps
  const canSave = editable && tested === values && t?.ok && t.data.ok && reason.trim() && !errors.length && !badOv;
  const fire = (action: (f: FormData) => void) => {
    const fd = new FormData();
    fd.set("agent", cfg.agent);
    fd.set("values", values.slice(0, values.length - ovOut.length));
    if (showRules) fd.set("overrides", ovOut);
    fd.set("sample", smp);
    fd.set("reason", reason);
    if (cfg.principal) fd.set("principal", cfg.principal);
    startTransition(() => action(fd));
  };
  if (!keys.length && !showRules) return <p className="text-xs text-muted">{tr(lang, "조직 설정 파라미터 없음 — 매니페스트 spec.config 미선언", "No organization settings — manifest declares no spec.config")}</p>;
  const r = t?.ok ? t.data : null;
  return (
    <div className="space-y-3 text-sm" data-testid="agent-settings">
      {cfg.principal && <p className="text-xs font-semibold" style={{ color: "#3b6fd8" }}>{tr(lang, `보호 대상 ${cfg.principal} 의 계약(byPrincipal) — 이 주체의 요청에는 공통 값보다 우선`, `Contract for ${cfg.principal} (byPrincipal) — overrides shared values for this principal's requests`)}</p>}
      <p className="text-xs text-muted">{tr(lang, `정책 ${cfg.policy} 의 agentParams.${cfg.agent} — 관문에서는 정책 값이 요청 값보다 우선(호출자가 허용목록을 넓히거나 임계를 낮출 수 없음). 비우면 엔진 기본값.`,
        `agentParams.${cfg.agent} in policy ${cfg.policy} — at the gate the policy value wins over request params (callers cannot widen allowlists or lower thresholds). Empty = engine default.`)}</p>
      {cfg.relocated && <p className="text-xs" style={{ color: "#9d6105" }}>{tr(lang, "이 에이전트는 상시 계열로 재배치됨 — 응답 후 판정(차단 불가)", "Relocated to the continuous series — judged after the response (cannot block)")}</p>}
      {showRules && <RuleTable cfg={cfg} ov={ov} set={setOv} editable={editable} />}
      {showRules && badOv && <p role="alert" className="text-xs text-red-600">{tr(lang, "임계는 0~1", "Threshold must be 0–1")}</p>}
      <div className="grid grid-cols-2 gap-3">
        {keys.map((k) => <Field key={k} k={k} p={cfg.schema[k]} text={texts[k] ?? ""} set={(s) => setTexts({ ...texts, [k]: s })} err={parsed[k].err} current={k in cfg.values} editable={editable} />)}
      </div>
      {editable && (
        <>
          <label className="block text-xs">{tr(lang, "표본 요청 JSON (선택 — 현재·변경 판정 비교)", "Sample request JSON (optional — compare current vs draft)")}
            <textarea className="input mono mt-1 h-20 w-full text-xs" value={smp} onChange={(e) => setSmp(e.target.value)} spellCheck={false} /></label>
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" className="btn btn-secondary" disabled={testing || !!errors.length || badOv} onClick={() => fire(testAction)} data-testid="cfg-test">
              {tr(lang, "변경 시험 (저장 안 함)", "Test change (no save)")}</button>
            <input className="input h-8 flex-1 text-xs" value={reason} onChange={(e) => setReason(e.target.value)} placeholder={tr(lang, "변경 사유 (원장 기록)", "Reason (recorded in the ledger)")} aria-label="reason" />
            <button type="button" className="btn btn-primary" disabled={!canSave || saving} onClick={() => fire(saveAction)} data-testid="cfg-save">
              {tr(lang, "배포 (새 정책 버전)", "Deploy (new policy version)")}</button>
          </div>
          {!canSave && <p className="text-xs text-muted">{tr(lang, "배포 = 현재 값으로 변경 시험 통과 + 사유 입력 후. 2초(캐시 TTL) 안에 모든 관문 반영.", "Deploy after the current values pass the test and a reason is entered. All gates pick it up within 2 s (cache TTL).")}</p>}
        </>
      )}
      {t && !t.ok && <p role="alert" className="text-red-600">{t.error}</p>}
      {r && (
        <div className="card space-y-2 p-3 text-xs" data-testid="cfg-result">
          <div><b>{tr(lang, `정책 단위 시험 ${r.tests.passed}/${r.tests.total}`, `Policy unit tests ${r.tests.passed}/${r.tests.total}`)}</b> {r.ok ? "✓" : <span role="alert" className="text-red-600">{tr(lang, "실패 — 배포 차단", "failed — deploy blocked")}</span>}</div>
          <table className="grid-table"><thead><tr><th>{tr(lang, "코퍼스", "Corpus")}</th><th>{tr(lang, "표본", "Samples")}</th><th>{tr(lang, "현재", "Current")}</th><th>{tr(lang, "변경 후", "After")}</th></tr></thead>
            <tbody>
              <tr><td>{tr(lang, "골든(정상) — 위험 판정", "Golden (benign) — flagged")}</td><td>{r.impact.golden.total}</td><td>{r.impact.golden.flaggedBefore}</td>
                <td style={{ color: r.impact.golden.flaggedAfter > r.impact.golden.flaggedBefore ? V.block : undefined }}>{r.impact.golden.flaggedAfter}</td></tr>
              <tr><td>{tr(lang, "공격 — 탐지", "Attacks — detected")}</td><td>{r.impact.attacks.total}</td><td>{r.impact.attacks.detectedBefore}</td>
                <td style={{ color: r.impact.attacks.detectedAfter < r.impact.attacks.detectedBefore ? V.block : undefined }}>{r.impact.attacks.detectedAfter}</td></tr>
            </tbody></table>
          {r.impact.changed.length > 0 && <ul>{r.impact.changed.map((c: any) => <li key={c.set + c.name}>{c.set} · {c.name}: <b style={{ color: V[c.before] }}>{c.before}</b> → <b style={{ color: V[c.after] }}>{c.after}</b></li>)}</ul>}
          {r.sample && <div>{tr(lang, "표본", "Sample")}: <b style={{ color: V[r.sample.current.verdict] }}>{r.sample.current.verdict}</b> ({r.sample.current.ruleId}) → <b style={{ color: V[r.sample.draft.verdict] }}>{r.sample.draft.verdict}</b> ({r.sample.draft.ruleId})</div>}
          {r.diff && <pre tabIndex={0} className="mono max-h-48 overflow-auto rounded bg-[#f6f7f9] p-2 text-[11px]">{r.diff}</pre>}
        </div>
      )}
      {d && (d.ok
        ? <p className="text-xs" data-testid="cfg-deployed">{d.data.changed ? tr(lang, `배포됨 — ${d.data.policy} (시험 ${d.data.tests.passed}/${d.data.tests.total})`, `Deployed — ${d.data.policy} (tests ${d.data.tests.passed}/${d.data.tests.total})`) : tr(lang, "변경 없음 — 같은 본문", "No change — same body")}</p>
        : <p role="alert" className="text-xs text-red-600">{d.error}</p>)}
    </div>
  );
}
