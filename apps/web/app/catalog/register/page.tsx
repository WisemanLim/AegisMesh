// SCR-C03 에이전트 등록 — 서명 번들 제출 → R1~R6 심사 결과(스테퍼).
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { registerBundle } from "@/lib/actions";
import { api, safe } from "@/lib/api";
import { t, tr, LX } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";

import { L } from "@/lib/i18n";

const STEPS = [["R1", "매니페스트 검증"], ["R2", "서명·출처"], ["R3", "정적 심사"], ["R4", "격리 시험"], ["R5", "품질 판정"], ["R6", "카탈로그 공개"], ["R7", "적용(사용자)"]];

export default async function Register({ searchParams }: { searchParams: Promise<{ msg?: string; agent?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const sp = await searchParams;
  const agentId = sp.agent ?? sp.msg?.match(/ (x\d{2}|d\d{1,2}-\d{2}) /)?.[1];
  const [pubs, reviews] = await Promise.all([
    safe(api("/v1/publishers"), { items: [] as any[] }),
    agentId ? safe(api(`/v1/agents/${agentId}/reviews`), { items: [] as any[] }) : Promise.resolve({ data: { items: [] as any[] } }),
  ]);
  const last = reviews.data.items[0];
  const ro = !can(user, "agent.register");
  return (
    <>
      <PageHeader crumb={`${t(lang, "catalog")} › ${t(lang, "register")}`} title={tr(lang, "에이전트 등록 7단계", "Agent registration (7 stages)")} />
      {sp.msg && <div className="mb-3"><Banner tone={sp.msg.startsWith(L(lang, "실패")) ? "danger" : "info"}>{L(lang, sp.msg)}</Banner></div>}
      <ol className="mb-4 flex gap-2 text-xs" aria-label={L(lang, "등록 단계")}>
        {STEPS.map(([k, label]) => {
          const st = last?.stages?.[k]?.result;
          const color = st === "passed" || st === "published" ? "var(--verdict-allow)" : st === "failed" ? "var(--verdict-block)" : st ? "var(--verdict-approval)" : "var(--line)";
          return <li key={k} className="flex-1 rounded-md border-2 p-2 text-center" style={{ borderColor: color }}><b>{k}</b> {L(lang, label)}<div className="text-muted">{st ?? "—"}</div></li>;
        })}
      </ol>
      {last && (
        <div className="card mb-4 p-4 text-sm">
          <div className="mb-2 font-semibold">{L(lang, "최근 심사 ")}{last.id} · {LX(lang, last.agentId)} v{LX(lang, last.version)} → <Chip tone="primary">{LX(lang, last.outcome)}</Chip></div>
          <ul className="space-y-1 text-xs">{Object.entries(last.stages).map(([k, v]: any) => <li key={k}><b>{k}</b> {LX(lang, v.result)} — {LX(lang, v.detail)}{v.issues?.length ? ` · ${v.issues.join("; ")}` : ""}</li>)}</ul>
        </div>
      )}
      <div className="grid grid-cols-[1fr_320px] gap-4">
        <form action={registerBundle} className="card space-y-2 p-4 text-sm">
          <h2 className="font-semibold">{L(lang, "서명 번들 (aegismesh.io/AgentBundle/v1)")}</h2>
          <textarea name="bundle" required rows={14} className="mono w-full rounded-md border border-line p-2" aria-label="bundle"
            placeholder={L(lang, "python -m aegis bundle agents/<dir> --key acme.key --key-id pub-acme > bundle.json  의 내용을 붙여넣기")} />
          <button className="btn btn-primary" disabled={ro} title={ro ? t(lang, "readOnly") : undefined}>{L(lang, "심사 제출")}</button>
          <p className="text-xs text-muted">{L(lang, "R3 위반·L1 이상 격리 요구는 보류(사람 검토), R5 미달은 경보 전용으로만 등록된다.")}</p>
        </form>
        <aside className="card p-4 text-sm">
          <h2 className="mb-2 font-semibold">{L(lang, "신뢰 게시자 (R2)")}</h2>
          {pubs.data.items.length === 0 ? <p className="text-xs text-muted">{L(lang, "등록된 게시자 키 없음 — POST /v1/publishers")}</p> :
            <ul className="space-y-1 text-xs">{pubs.data.items.map((p: any) => <li key={p.keyId}><b>{LX(lang, p.name)}</b> <span className="mono">{LX(lang, p.keyId)}</span></li>)}</ul>}
        </aside>
      </div>
    </>
  );
}
