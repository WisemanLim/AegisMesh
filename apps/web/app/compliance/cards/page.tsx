// SCR-N07 시스템·모델 카드 — 메타데이터에서 ko·en 카드 자동 생성, 변경 감지 → 갱신 필요(배포 게이트 차단, MSG-021), 검토 → 승인 후 공개(판 이력 원장).
import Link from "next/link";
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { t as tk, tr } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { generateCards, publishCard } from "../actions";

const ST: Record<string, [string, string, string]> = { latest: ["최신", "Current", "var(--verdict-allow)"], draft: ["초안", "Draft", "var(--sev-info)"],
  review: ["검토 중", "In review", "var(--verdict-approval)"], "needs-update": ["갱신 필요", "Needs update", "#9d6105"], missing: ["없음", "Missing", "var(--verdict-block)"] };
const SEC: [string, string, string][] = [["purpose", "목적·사용 범위", "Purpose & scope"], ["model", "모델·버전", "Model & version"], ["data", "데이터", "Data"],
  ["evaluation", "평가 결과", "Evaluation"], ["limits", "제약·알려진 한계", "Limitations"], ["controls", "안전 통제", "Safety controls"], ["fairness", "공정성", "Fairness"]];
const AUD: [string, string, string][] = [["internal", "내부", "Internal"], ["regulator", "규제기관 제출", "Regulator"], ["external", "외부 공개", "External"]];
const SECTION_OF: Record<string, string[]> = { purpose: ["purpose"], model: ["model"], data: ["data"], controls: ["controls", "evaluation"] };

export default async function Cards({ searchParams }: { searchParams: Promise<{ s?: string; msg?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const sp = await searchParams;
  const { data, error } = await safe(api("/v1/compliance/cards"), null as any);
  const write = can(user, "compliance.write");
  const items: any[] = data?.items ?? [];
  const sel = items.find((x) => x.subject === sp.s) ?? items.find((x) => x.status !== "missing") ?? items[0];
  const stale = items.filter((x) => x.status === "needs-update");
  const stL = (s: string) => tr(lang, ...(ST[s] ?? [s, s, ""]).slice(0, 2) as [string, string]);
  const hot = new Set<string>(sel?.status === "needs-update" ? Object.entries(SECTION_OF).filter(([k]) => sel.changes.some((c: string) => c.startsWith(`${k}.`) || c.startsWith(`${k}:`))).flatMap(([, v]) => v) : sel?.changedSections ?? []);
  return (
    <>
      <PageHeader crumb={`${tk(lang, "groupGov")} › ${tr(lang, "컴플라이언스", "Compliance")} › ${tr(lang, "카드", "Cards")}`} title={tr(lang, "시스템·모델 카드", "System & model cards")}
        actions={write ? <form action={generateCards}><input type="hidden" name="s" value={sel?.subject ?? ""} /><button className="btn btn-primary" data-testid="generate">{tr(lang, "자동 생성", "Auto-generate")}</button></form> : undefined} />
      {sp.msg && <div className="mb-3"><Banner tone={/^(실패|Failed)/.test(sp.msg) ? "danger" : "info"}>{sp.msg}</Banner></div>}
      {error && <p className="mb-3 text-sm text-red-600">{error}</p>}
      {data && !data.deployGate.ok && (
        <div className="mb-3" data-testid="gate-warning"><Banner tone="warn">{tr(lang, `카드 갱신 전까지 배포 게이트 차단 (C4 · MSG-021) — ${data.deployGate.blocked.join(", ")}`, `Deploy gate blocked until the cards are refreshed (C4 · MSG-021) — ${data.deployGate.blocked.join(", ")}`)}</Banner></div>
      )}
      <div className="grid grid-cols-[440px_1fr] gap-4">
        <div className="space-y-4">
          <section className="card overflow-hidden text-sm" data-testid="card-list">
            <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "카드", "Card")}</th><th>{tr(lang, "판", "Ver")}</th><th>{tr(lang, "상태", "Status")}</th><th>{tr(lang, "공개", "Published")}</th></tr></thead>
              <tbody>{items.length === 0 ? <tr><td colSpan={4} className="text-muted">{tr(lang, "보호 대상·모델 점검 대상이 없다 — 즉시 사용 ②·D7 무결성에서 등록", "No protected targets or model scan targets — register them in instant use ② or D7 integrity")}</td></tr> : items.map((x) => (
                <tr key={x.subject} className={x.subject === sel?.subject ? "bg-primary-soft" : undefined}>
                  <td><Link className="mono text-primary" href={`/compliance/cards?s=${encodeURIComponent(x.subject)}`}>{x.subject}</Link> <span className="text-muted">{x.type === "system" ? tr(lang, "시스템", "system") : tr(lang, "모델", "model")}</span></td>
                  <td>{x.version ? `v${x.version}` : "—"}</td><td><b style={{ color: ST[x.status]?.[2] }}>{stL(x.status)}</b></td>
                  <td>{x.published ? `v${x.published.version} · ${fmtTime(x.published.at).slice(0, 10)}` : "—"}</td></tr>))}</tbody></table>
          </section>
          <section className="card p-4 text-sm" data-testid="changes">
            <h2 className="mb-2 font-semibold">{tr(lang, "변경 감지 · 갱신 강제", "Change detection · forced refresh")}</h2>
            {stale.length === 0 ? <p className="text-xs text-muted">{tr(lang, "변경 없음 — 모델·데이터셋·정책·프로파일 지문 일치", "No changes — model, dataset, policy and profile fingerprints match")}</p>
              : stale.map((x) => (<div key={x.subject} className="mb-2 text-xs"><b className="mono">{x.subject}</b> {tr(lang, "변경:", "changed:")}<ul className="ml-3 list-disc">{x.changes.map((c: string) => <li key={c} className="mono">{c}</li>)}</ul></div>))}
          </section>
        </div>
        {sel && (
          <section className="card p-4 text-sm" data-testid="card-detail">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <h2 className="font-semibold">{sel.subject} {sel.type === "system" ? tr(lang, "시스템 카드", "system card") : tr(lang, "모델 카드", "model card")} {sel.version ? `v${sel.version}` : ""}</h2>
              <Chip tone="primary">{stL(sel.status)}</Chip><Chip>ko · en</Chip>
              {sel.published && <span className="text-xs text-muted">{tr(lang, `마지막 공개 ${fmtTime(sel.published.at)} · ${sel.published.audiences.join(", ")}`, `Last published ${fmtTime(sel.published.at)} · ${sel.published.audiences.join(", ")}`)}</span>}
              {sel.version && <span className="ml-auto flex gap-2 text-xs"><a className="text-primary" href={`/compliance/cards/doc?s=${encodeURIComponent(sel.subject)}&lang=ko`}>{tr(lang, "문서 ko ↓", "Doc ko ↓")}</a><a className="text-primary" href={`/compliance/cards/doc?s=${encodeURIComponent(sel.subject)}&lang=en`}>{tr(lang, "문서 en ↓", "Doc en ↓")}</a></span>}
            </div>
            {!sel.sections ? <p className="text-xs text-muted">{tr(lang, "카드 없음 — 자동 생성", "No card yet — auto-generate")}</p> : (
              <table className="grid-table text-xs"><tbody>{SEC.map(([k, ko, en]) => (
                <tr key={k} style={hot.has(k) ? { background: "#fdf3e6" } : undefined}><td className="w-36 text-muted">{tr(lang, ko, en)}{hot.has(k) ? <b style={{ color: "#9d6105" }}> {sel.status === "needs-update" ? tr(lang, "변경", "changed") : tr(lang, "새 판", "new")}</b> : null}</td>
                  <td>{sel.sections[k]?.[lang] ?? "—"}</td></tr>))}</tbody></table>)}
            {sel.status === "needs-update" && <p className="mt-2 text-xs" style={{ color: "#9d6105" }}>{tr(lang, "⚠ 카드 갱신 전까지 이 대상의 배포 게이트가 막힌다 — 자동 생성으로 새 판을 만든 뒤 검토·공개", "⚠ This target's deploy gate stays blocked until the card is refreshed — auto-generate a new version, then review and publish")}</p>}
            {write && sel.version && (
              <form action={publishCard} className="mt-3 flex flex-wrap items-center gap-3 text-xs" data-testid="publish-form">
                <input type="hidden" name="s" value={sel.subject} />
                {AUD.map(([v, ko, en]) => <label key={v} className="flex items-center gap-1"><input type="checkbox" name="audiences" value={v} defaultChecked={v === "internal"} />{tr(lang, ko, en)}</label>)}
                <button className="btn btn-primary h-7 text-xs" disabled={sel.status === "needs-update" || sel.status === "review" || sel.status === "missing"}
                  title={sel.status === "needs-update" ? tr(lang, "갱신 먼저 (MSG-021)", "Refresh first (MSG-021)") : undefined}>{tr(lang, "검토 요청 → 승인 후 공개", "Request review → publish after approval")}</button>
                {sel.pending && <Link className="text-primary" href={`/approvals/${sel.pending}`}>{tr(lang, `승인 대기 ${sel.pending}`, `Pending ${sel.pending}`)}</Link>}
                <span className="text-muted">{tr(lang, "외부 공개는 승인자 확인 · 판 이력은 원장(덮어쓰기 없음)", "External publication needs an approver · version history in the ledger (no overwrite)")}</span>
              </form>
            )}
            {sel.versions?.length > 0 && (
              <div className="mt-3 text-xs" data-testid="versions"><b>{tr(lang, "판 이력", "Versions")}</b> {sel.versions.map((x: any) => (
                <span key={x.version} className="ml-2"><a className="text-primary" href={`/compliance/cards/doc?s=${encodeURIComponent(sel.subject)}&lang=${lang}&v=${x.version}`}>v{x.version}</a> <span className="text-muted">{fmtTime(x.at).slice(0, 16)}{x.changed?.length ? ` (${x.changed.join(", ")})` : ""}</span></span>))}</div>
            )}
          </section>
        )}
      </div>
    </>
  );
}
