// SCR-C04 즉시 사용 ① 프로파일 선택 — 5종(+사용자 정의) 비교, 현재 적용 안내, 선택 프로파일의 변경 비교(추가 에이전트·지연·증적·외부 모델·격리).
import Link from "next/link";
import { Banner, Chip } from "@/components/Badges";
import { InstantSteps, wizardHref } from "@/components/InstantSteps";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { t as tk, tr, nm, LX } from "@/lib/i18n";
import { prefs } from "@/lib/session";

export default async function InstantProfiles({ searchParams }: { searchParams: Promise<{ p?: string; t?: string }> }) {
  const { lang } = await prefs();
  const { p, t } = await searchParams;
  const [profiles, targets, apps] = await Promise.all([
    safe(api("/v1/profiles"), { items: [] as any[] }), safe(api("/v1/targets"), { items: [] as any[] }), safe(api("/v1/applications"), { items: [] as any[] }),
  ]);
  const cmp = p ? await safe(api(`/v1/profiles/${encodeURIComponent(p)}/compare${t ? `?target=${encodeURIComponent(t)}` : ""}`), null as any) : { data: null };
  const c = cmp.data;
  const active = apps.data.items;
  return (
    <>
      <PageHeader crumb={`${tk(lang, "instant")} › ${tr(lang, "프로파일", "Profile")}`} title={tr(lang, "즉시 사용 ① 프로파일 선택", "Instant use ① choose a profile")} />
      <InstantSteps lang={lang} at={1} p={p} t={t} next={p ? wizardHref("targets", p, t) : undefined} nextOk={!!p && (c?.isolationOk ?? true)}
        nextNote={c && !c.isolationOk ? tr(lang, "필요 격리 노드 없음 (MSG-006)", "Required isolation nodes missing (MSG-006)") : undefined} />
      <div className="mb-3" data-testid="current-banner">
        <Banner tone="info">{active.length === 0 ? tr(lang, "현재 적용된 프로파일 없음 — 처음이면 관측만(minimal-visibility) 또는 chatbot-baseline 부분 차단부터 (ST-02)", "No profile applied yet — start with observe-only (minimal-visibility) or chatbot-baseline partial blocking (ST-02)")
          : tr(lang, `현재 적용: ${active.map((a: any) => `${a.profile} → ${a.target} (${a.stage}, ${a.agents.length}종)`).join(" · ")} — 바꾸면 미리보기(③) 후 단계 적용`,
            `Applied now: ${active.map((a: any) => `${a.profile} → ${a.target} (${a.stage}, ${a.agents.length})`).join(" · ")} — after a change, preview (③) then apply by stage`)}</Banner>
      </div>
      <div role="radiogroup" aria-label="profiles" className="grid grid-cols-3 gap-3 xl:grid-cols-6" data-testid="profile-cards">
        {profiles.data.items.map((x: any) => {
          const on = x.id === p;
          return (
            <Link key={x.id} role="radio" aria-checked={on} href={wizardHref("profiles", x.id, t)} data-profile={x.id}
              className={`card flex flex-col gap-1.5 p-3 text-sm ${on ? "ring-2 ring-primary" : "hover:ring-1 hover:ring-line"}`}>
              <div className="flex items-center justify-between"><b>{nm(lang, x)}</b>{on && <Chip tone="primary">✓</Chip>}</div>
              <div className="mono text-xs text-muted">{x.id}{x.extends ? ` ⊃ ${x.extends}` : ""}{x.custom ? ` · ${tr(lang, "사용자 정의", "custom")}` : ""}</div>
              <div className="text-lg font-bold">{x.available}<span className="text-xs font-normal text-muted">/{x.items} {tr(lang, "종 포함", "agents")}</span></div>
              <div className="text-xs">{tr(lang, "차단 정책", "Blocking")}: {LX(lang, x.blocking ?? "—")}</div>
              <div className="text-xs text-muted">{tr(lang, "예상 지연", "Expected latency")}: {LX(lang, x.expectedLatency ?? "—")}</div>
              <div className="text-xs text-muted">{tr(lang, "기본 단계", "Default stage")}: {x.defaultStage}{x.region?.modelEgress === "deny" ? ` · ${tr(lang, "외부 모델 금지", "no external model")}` : ""}</div>
            </Link>
          );
        })}
      </div>
      {p && !c && <p className="mt-3 text-sm text-red-600">{tr(lang, `프로파일 ${p} 없음`, `Profile ${p} not found`)}</p>}
      {c && (
        <section className="card mt-4 grid grid-cols-[1fr_1fr] gap-4 p-4 text-sm" data-testid="compare">
          <div>
            <h2 className="mb-2 font-semibold">{tr(lang, "변경 비교", "Change comparison")} — {c.current ? `${c.current.profile} (${c.current.stage})` : tr(lang, "미적용", "none")} → {c.profile}</h2>
            <form className="mb-2 flex items-center gap-2 text-xs" action="/instant/profiles">
              <input type="hidden" name="p" value={p} />
              <label>{tr(lang, "보호 대상 기준", "Against target")}
                <select name="t" defaultValue={t ?? ""} className="input ml-1 h-7 text-xs">
                  <option value="">{tr(lang, "(대상 없음 — 전체 신규)", "(no target — all new)")}</option>
                  {targets.data.items.map((x: any) => <option key={x.id} value={x.name}>{x.name}{x.application ? ` · ${x.application.profile}` : ""}</option>)}
                </select></label>
              <button className="btn btn-secondary h-7 text-xs">{tr(lang, "비교", "Compare")}</button>
            </form>
            <table className="grid-table text-xs"><tbody>
              <tr><td className="w-44 text-muted">{tr(lang, "에이전트", "Agents")}</td><td>{c.agents}{tr(lang, "종", "")} · <b>+{c.added.length}</b> / −{c.removed.length}{c.missing.length ? ` · ${tr(lang, "미구현", "missing")} ${c.missing.length}` : ""}</td></tr>
              <tr><td className="w-44 text-muted">{tr(lang, "도메인별 추가", "Added by domain")}</td><td>{Object.entries(c.addedByDomain).filter(([, n]) => (n as number) > 0).map(([d, n]) => `${d} +${n}`).join(" · ") || "—"}</td></tr>
              <tr><td className="w-44 text-muted">{tr(lang, "관문 지연 상한", "Gate latency budget")}</td><td>{Object.entries(c.latencyMs).map(([g, ms]) => `${g} ${ms}ms`).join(" · ")}</td></tr>
              <tr><td className="w-44 text-muted">{tr(lang, "증적 보존", "Evidence retention")}</td><td>{c.evidence.from?.retentionDays ? `${c.evidence.from.retentionDays}${tr(lang, "일", "d")}` : "—"} → {c.evidence.to?.retentionDays ? `${c.evidence.to.retentionDays}${tr(lang, "일", "d")}` : "—"}{c.evidence.to?.payload ? ` · ${tr(lang, "원문", "payload")} ${c.evidence.to.payload}` : ""}</td></tr>
              <tr><td className="w-44 text-muted">{tr(lang, "외부 모델", "External model")}</td><td>{c.modelEgress.from} → <b style={{ color: c.modelEgress.to === "deny" ? "var(--verdict-block)" : undefined }}>{c.modelEgress.to}</b>{c.modelEgress.to === "deny" ? ` (MSG-013)` : ""}</td></tr>
              <tr><td className="w-44 text-muted">{tr(lang, "격리 요구", "Isolation")}</td><td>{c.isolation.join(" · ")} {c.isolationOk ? "✓" : <b style={{ color: "var(--verdict-block)" }}>{tr(lang, "✗ 필요 격리 노드 없음 (MSG-006)", "✗ isolation nodes missing (MSG-006)")}</b>}</td></tr>
              <tr><td className="w-44 text-muted">{tr(lang, "승인 필요", "Needs approval")}</td><td>{c.approvalNeeded.length ? c.approvalNeeded.map((x: string) => <div key={x}>{x === "evidenceMasked" ? tr(lang, "증적 원문 masked 보존 → 열람 2인 승인", "Evidence payload kept masked → viewing needs two approvals")
                : x === "modelEgressDeny" ? tr(lang, "외부 모델 금지 — 대상의 외부 모델 호출은 승인 후", "External model denied — a target's external calls need approval") : x}</div>) : "—"}</td></tr>
            </tbody></table>
          </div>
          <div>
            <h2 className="mb-2 font-semibold">{tr(lang, "추가되는 에이전트", "Agents added")} ({c.added.length})</h2>
            <div className="flex max-h-56 flex-wrap gap-1 overflow-auto">{c.added.map((a: string) => <Link key={a} href={`/catalog/${a}`}><Chip>{a}</Chip></Link>)}</div>
            {c.removed.length > 0 && <><h3 className="mb-1 mt-2 text-xs font-semibold">{tr(lang, "빠지는 에이전트", "Agents removed")}</h3><div className="flex flex-wrap gap-1">{c.removed.map((a: string) => <Chip key={a}>{a}</Chip>)}</div></>}
            <Link className="btn btn-secondary mt-3 h-8 text-xs" href={`/profiles/edit?p=${p}`}>{tr(lang, "복제해서 편집 (extends)", "Clone & edit (extends)")}</Link>
          </div>
        </section>
      )}
      {!p && <p className="mt-3 text-xs text-muted">{tr(lang, "카드 하나를 고르면 변경 비교가 열리고 다음 단계가 켜진다.", "Pick a card to open the comparison and enable the next step.")}</p>}
    </>
  );
}
