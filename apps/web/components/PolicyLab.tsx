"use client";
// 정책 편집기(SCR-D04)·판정 시뮬레이터(SCR-D05)·프로파일 편집기(SCR-C08) — 시험·검증 결과는 저장 없이 화면에만.
// React 19 는 폼 액션 후 비제어 입력을 초기화한다 → 편집 내용은 제어 상태로 두고, 시뮬레이터는 직접 제출한다.
import { startTransition, useActionState, useState } from "react";
import { deployPolicy, saveProfile, simulate, testPolicy, validateProfile } from "@/app/policies/actions";

import { L, LX } from "@/lib/i18n";
import { useLang } from "@/lib/lang";

const V: Record<string, string> = { allow: "#257a6e", alert: "#9d6105", transform: "#3b6fd8", require_approval: "#8a4fd8", block: "#c03333" };
const Verdict = ({ v }: { v?: string | null }) => <b style={{ color: V[v ?? ""] ?? "inherit" }}>{v ?? "—"}</b>;

function Results({ rows }: { rows: any[] }) {
  const lang = useLang();
  return (
    <table className="grid-table mt-2 text-xs">
      <thead><tr><th>{L(lang, "시험")}</th><th>{L(lang, "관문")}</th><th>{L(lang, "기대")}</th><th>{L(lang, "결과")}</th><th>{L(lang, "근거")}</th></tr></thead>
      <tbody>{rows.map((r) => (
        <tr key={r.name}><td>{r.ok ? "✓" : "✗"} {LX(lang, r.name)}</td><td>{LX(lang, r.gate)}</td><td><Verdict v={r.expect} /></td><td><Verdict v={r.got} /></td>
          <td className="mono">{LX(lang, r.error ?? r.rules?.join(", "))}</td></tr>
      ))}</tbody>
    </table>
  );
}

export function PolicyEditor({ initial }: { initial: string }) {
  const lang = useLang();
  const [yaml, setYaml] = useState(initial);
  const [t, testAction, testing] = useActionState(testPolicy, null);
  const [d, deployAction, deploying] = useActionState(deployPolicy, null);
  const failed = d && !d.ok ? (d.data as any)?.results : null;
  return (
    <form className="grid grid-cols-[1fr_420px] gap-4">
      <textarea name="yaml" value={yaml} onChange={(e) => setYaml(e.target.value)} spellCheck={false} className="input mono h-[560px] w-full text-xs" aria-label="policy yaml" />
      <div className="space-y-3 text-sm">
        <div className="flex gap-2">
          <button formAction={testAction} className="btn btn-secondary" disabled={testing}>{L(lang, "단위 시험")}</button>
          <button formAction={deployAction} className="btn btn-primary" disabled={deploying}>{L(lang, "배포 (시험 통과 시)")}</button>
        </div>
        {t && (t.ok ? (
          <div className="card p-3" data-testid="policy-test">
            <b>{L(lang, "단위 시험 ")}{LX(lang, t.data.passed)}/{t.data.total}</b> {t.data.total === 0 && <span className="text-xs text-muted">{L(lang, "— tests 없음 (배포 가능하나 권장하지 않음)")}</span>}
            <Results rows={t.data.results} />
            {t.data.diff && <pre tabIndex={0} className="mono mt-2 max-h-56 overflow-auto rounded bg-[#f6f7f9] p-2 text-[11px]">{LX(lang, t.data.diff)}</pre>}
          </div>
        ) : <p role="alert" className="text-red-600">{LX(lang, t.error)}</p>)}
        {d && (d.ok ? (
          <div className="card p-3" data-testid="policy-deployed">{L(lang, "배포됨 ")}<b className="mono">{LX(lang, d.data.tenant)}/{d.data.id}@v{LX(lang, d.data.version)}</b>{L(lang, " · 시험 ")}{LX(lang, d.data.tests.passed)}/{d.data.tests.total}{L(lang, " · 관문에 즉시 반영")}</div>
        ) : (
          <div role="alert" className="card p-3 text-red-600" data-testid="policy-blocked">{L(lang, "배포 차단: ")}{LX(lang, d.error)}{failed && <Results rows={failed} />}</div>
        ))}
        <p className="text-xs text-muted">{L(lang, "tests: [{name, gate, request, agents?|target?, stage?, expect}] — 실제 관문 경로로 재생. 하나라도 다르면 배포를 막는다. 원장에는 배포만 기록.")}</p>
      </div>
    </form>
  );
}

export function Simulator({ draft, sample }: { draft: string; sample: string }) {
  const lang = useLang();
  const [s, action, pending] = useActionState(simulate, null);
  const r = s?.ok ? s.data : null;
  const submit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    startTransition(() => action(fd));
  };
  return (
    <div className="grid grid-cols-[440px_1fr] gap-4">
      <form onSubmit={submit} className="card space-y-2 p-4 text-sm">
        <div className="grid grid-cols-2 gap-2">
          <label>{L(lang, "관문")}<select name="gate" className="input mt-1 w-full" defaultValue="tool">{["input", "tool", "output", "offline"].map((g) => <option key={g}>{g}</option>)}</select></label>
          <label>{L(lang, "단계")}<select name="stage" className="input mt-1 w-full" defaultValue=""><option value="">{L(lang, "적용값")}</option>{["observe", "partial", "enforce"].map((g) => <option key={g}>{g}</option>)}</select></label>
        </div>
        <input name="target" placeholder={L(lang, "대상 (프로파일 적용)")} className="input w-full" aria-label="target" />
        <input name="agents" placeholder={L(lang, "또는 에이전트 (쉼표, 예: d3-01,d3-05)")} className="input w-full" aria-label="agents" />
        <label className="block">{L(lang, "요청 JSON")}<textarea name="request" defaultValue={sample} spellCheck={false} className="input mono mt-1 h-40 w-full text-xs" /></label>
        <label className="block">{L(lang, "초안 정책 YAML (선택 — 배포 정책과 비교)")}<textarea name="draft" defaultValue={draft} spellCheck={false} className="input mono mt-1 h-40 w-full text-xs" /></label>
        <button className="btn btn-primary w-full justify-center" disabled={pending}>{L(lang, "평가 (차단·기록 없음)")}</button>
      </form>
      <div className="space-y-3 text-sm" data-testid="sim-result">
        {s && !s.ok && <p role="alert" className="text-red-600">{LX(lang, s.error)}</p>}
        {r && (
          <>
            <div className="card flex flex-wrap gap-4 p-3">
              <span>{L(lang, "배포 ")}<span className="mono text-xs">{LX(lang, r.policy)}</span> → <Verdict v={r.deployed.verdict} /></span>
              {r.draft && <span>{L(lang, "초안 → ")}<Verdict v={r.draft.verdict} /></span>}
              <span className="text-xs text-muted">{LX(lang, r.gate)} · {LX(lang, r.stage)} · {LX(lang, r.profile ?? L(lang, "에이전트 지정"))} · {LX(lang, r.latencyMs)}ms / {LX(lang, r.budgetMs ?? "—")}ms{r.quarantine ? L(lang, " · 격리 {0}", r.quarantine) : ""}</span>
            </div>
            {r.changed && <div className="card p-3"><b>{L(lang, "정책 변경 영향 ")}{r.changed.length}{L(lang, "건")}</b>
              <ul className="mt-1 text-xs">{r.changed.map((c: any) => <li key={c.ruleId}><span className="mono">{LX(lang, c.ruleId)}</span>: <Verdict v={c.deployed} /> → <Verdict v={c.draft} /></li>)}</ul></div>}
            <table className="grid-table text-xs"><thead><tr><th>{L(lang, "에이전트")}</th><th>{L(lang, "규칙")}</th><th>{L(lang, "원판정")}</th><th>{L(lang, "유효(배포)")}</th>{r.draft && <th>{L(lang, "유효(초안)")}</th>}<th>{L(lang, "신뢰도")}</th><th>{L(lang, "사유")}</th></tr></thead>
              <tbody>{r.deployed.decisions.map((d: any, i: number) => {
                const f = r.findings.find((x: any) => x.id === d.findingId);
                return (<tr key={i}><td>{LX(lang, d.agent)}</td><td className="mono">{LX(lang, d.ruleId)}</td><td><Verdict v={d.original} /></td><td><Verdict v={d.effective} /></td>
                  {r.draft && <td><Verdict v={r.draft.decisions[i]?.effective} /></td>}<td>{LX(lang, f?.confidence ?? "—")}</td><td>{d.reasons.join("; ")}</td></tr>);
              })}</tbody></table>
            <div className="card p-3"><b>{L(lang, "정책 단위 시험 케이스로 저장")}</b><p className="text-xs text-muted">{L(lang, "편집기의 정책 YAML 에 붙여 넣는다 (저장은 배포 시).")}</p>
              <pre tabIndex={0} className="mono mt-1 overflow-auto rounded bg-[#f6f7f9] p-2 text-[11px]" data-testid="sim-testcase">{LX(lang, r.testCase)}</pre></div>
          </>
        )}
      </div>
    </div>
  );
}

export function ProfileEditor({ initial }: { initial: string }) {
  const lang = useLang();
  const [yaml, setYaml] = useState(initial);
  const [v, validateAction, validating] = useActionState(validateProfile, null);
  const [sv, saveAction, saving] = useActionState(saveProfile, null);
  const rep = v?.ok ? v.data : null;
  return (
    <form className="grid grid-cols-[1fr_460px] gap-4">
      <textarea name="yaml" value={yaml} onChange={(e) => setYaml(e.target.value)} spellCheck={false} className="input mono h-[520px] w-full text-xs" aria-label="profile yaml" />
      <div className="space-y-3 text-sm">
        <div className="flex gap-2">
          <button formAction={validateAction} className="btn btn-secondary" disabled={validating}>{L(lang, "검증")}</button>
          <button formAction={saveAction} className="btn btn-primary" disabled={saving}>{L(lang, "저장 (테넌트 프로파일)")}</button>
        </div>
        {sv && (sv.ok ? <div className="card p-3" data-testid="profile-saved">{L(lang, "저장됨 ")}<b className="mono">{sv.data.id}</b>{L(lang, " · 에이전트 ")}{sv.data.agents.length}{L(lang, "종 · 미구현 ")}{sv.data.missing.length}{L(lang, " — 즉시 사용에서 적용")}</div>
          : <p role="alert" className="text-red-600">{L(lang, "저장 실패: ")}{LX(lang, sv.error)}</p>)}
        {v && !v.ok && <p role="alert" className="text-red-600">{LX(lang, v.error)}</p>}
        {rep && (
          <div className="card space-y-2 p-3" data-testid="profile-report">
            <b>{rep.ok ? L(lang, "검증 통과") : L(lang, "검증 실패")}</b>{rep.ok && <span className="mono ml-2 text-xs">{rep.id}</span>}
            {rep.errors.map((e: string) => <p key={e} className="text-xs text-red-600">✗ {e}</p>)}
            {rep.warnings?.map((e: string) => <p key={e} className="text-xs" style={{ color: "#9d6105" }}>⚠ {e}</p>)}
            {rep.ok && (<>
              <p className="text-xs">{L(lang, "항목 ")}{rep.items.length}{L(lang, " · 에이전트 ")}{rep.agents.length}{L(lang, " · 미구현 ")}{rep.missing.length}{L(lang, " · 기본 단계 ")}{LX(lang, rep.defaultStage)}</p>
              <table className="grid-table text-xs"><thead><tr><th>{L(lang, "관문")}</th><th>{L(lang, "에이전트")}</th><th>{L(lang, "최대 에이전트 예산")}</th><th>{L(lang, "관문 예산")}</th></tr></thead>
                <tbody>{Object.entries(rep.gates).map(([g, x]: [string, any]) => <tr key={g}><td>{g}</td><td>{LX(lang, x.agents)}</td><td>{LX(lang, x.maxAgentBudgetMs)}ms</td><td>{LX(lang, x.gateBudgetMs ?? "—")}{x.withinBudget ? "" : " ⚠"}</td></tr>)}</tbody></table>
              <p className="text-xs">{L(lang, "승인 필요 항목: ")}{rep.approvalItems.join(", ") || L(lang, "없음")}</p>
              <p className="text-xs">{L(lang, "격리: 런타임 ")}{LX(lang, rep.isolation.runtime)}{L(lang, " · 기동 불가 ")}{rep.isolation.overRuntime.join(", ") || L(lang, "없음")}</p>
            </>)}
          </div>
        )}
      </div>
    </form>
  );
}
