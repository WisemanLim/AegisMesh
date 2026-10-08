// SCR-C02 에이전트 상세 — 매니페스트·엔진·실측 품질·규칙 + M1 실행 안내(SCR-C09).
import { notFound } from "next/navigation";
import { AgentSettings } from "@/components/AgentSettings";
import { Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { ApiError, api, safe } from "@/lib/api";
import { standardChips } from "@/lib/format";

import { L, nm, LX, tr } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { promoteAgent } from "../promote-actions";

export default async function AgentDetail({ params }: { params: Promise<{ id: string }> }) {
  const { lang } = await prefs();
  const { id } = await params;
  let a: any;
  try {
    a = await api(`/v1/agents/${id}`);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound();
    throw e;
  }
  const m = a.manifest;
  const [{ data: cfg }, user] = await Promise.all([safe(api(`/v1/agents/${id}/config`), null as any), me()]);
  return (
    <>
      <PageHeader crumb={L(lang, "카탈로그 › {0}", a.id)} title={`${a.id} ${nm(lang, a)}`}
        actions={a.origin === "api" && a.status === "alert_only" && can(user, "publisher") ? <form action={promoteAgent}><input type="hidden" name="id" value={a.id} />
          <input name="reason" required minLength={4} className="input mr-1 h-8 w-56 text-xs" placeholder={lang === "en" ? "Reason (accepting L1 instead of L3)" : "사유 (L3 대신 L1 감수)"} aria-label="promote reason" />
          <button className="btn btn-primary h-8 text-xs" data-testid="promote">{lang === "en" ? "Request blocking promotion (2 approvals)" : "차단 승격 요청 (2인)"}</button></form> : undefined} />
      {a.origin === "api" && a.status === "alert_only" && <div className="mb-3 rounded-lg border border-line bg-panel px-4 py-2 text-xs" data-testid="isolation-shortfall">{lang === "en"
        ? "Alert-only: registered without an L3 isolation node — R4 replayed in the L1 sandbox (isolation shortfall, OQ2). Blocking needs a two-person promotion."
        : "경보 전용 — L3 격리 노드 없이 등록(R4 를 L1 샌드박스로 대체, 격리 미달·OQ2). 차단 승격은 2인 승인."}</div>}
      <div className="grid grid-cols-3 gap-4">
        <section className="card col-span-2 p-4 text-sm">
          <h2 className="mb-2 font-semibold">{L(lang, "매니페스트")}</h2>
          <dl className="grid grid-cols-[140px_1fr] gap-y-1.5">
            <dt className="text-muted">{L(lang, "도식 추적")}</dt><dd>{LX(lang, m.metadata.source.domain)} · {LX(lang, m.metadata.source.item)}</dd>
            <dt className="text-muted">{L(lang, "계열·관문")}</dt><dd>{LX(lang, a.series)} · {LX(lang, a.gate)}{L(lang, " · 예산 ")}{LX(lang, a.latencyBudgetMs)}ms · fail_{LX(lang, a.failMode)}</dd>
            <dt className="text-muted">{L(lang, "격리")}</dt><dd>{LX(lang, a.isolation)}{L(lang, " (런타임 미달 시 기동 거부)")}</dd>
            <dt className="text-muted">{L(lang, "판정 유형")}</dt><dd>{m.spec.verdicts.join(", ")}</dd>
            <dt className="text-muted">{L(lang, "엔진")}</dt><dd>{m.spec.engines.available.map((e: any) => `${e.id}(${e.kind})`).join(", ")}{L(lang, " — 기본 ")}{LX(lang, m.spec.engines.default)}</dd>
            <dt className="text-muted">{L(lang, "어댑터")}</dt><dd>{m.spec.modes.join(", ")}</dd>
            <dt className="text-muted">{L(lang, "표준")}</dt><dd className="flex flex-wrap gap-1">{standardChips(a.standards).map((s) => <Chip key={s}>{s}</Chip>)}</dd>
          </dl>
          {a.rules && (
            <>
              <h2 className="mb-2 mt-5 font-semibold">{L(lang, "규칙")}</h2>
              <table className="grid-table"><tbody>
                {Object.entries(a.rules).map(([k, v]) => <tr key={k}><td className="mono w-64">{k}</td><td>{String((lang === "en" && a.rulesEn?.[k]) || v)}</td></tr>)}
              </tbody></table>
            </>
          )}
        </section>
        <aside className="space-y-4">
          <section className="card p-4 text-sm">
            <h2 className="mb-2 font-semibold">{L(lang, "실측 품질")}</h2>
            {a.quality ? (
              <dl className="grid grid-cols-2 gap-y-1">
                <dt className="text-muted">{L(lang, "골든셋")}</dt><dd>{LX(lang, a.quality.golden)}{L(lang, "건")}</dd>
                <dt className="text-muted">{L(lang, "공격셋")}</dt><dd>{LX(lang, a.quality.attacks)}{L(lang, "건")}</dd>
                <dt className="text-muted">{L(lang, "오탐률")}</dt><dd>{LX(lang, a.quality.falsePositiveRate)}</dd>
                <dt className="text-muted">{L(lang, "탐지율")}</dt><dd>{LX(lang, a.quality.detectionRate)}</dd>
                <dt className="text-muted">p95</dt><dd>{LX(lang, a.quality.p95Ms)}ms</dd>
                <dt className="text-muted">{L(lang, "게이트")}</dt><dd>{a.quality.pass ? "PASS" : "FAIL"}</dd>
              </dl>
            ) : <p className="text-muted">{L(lang, "심사 전 — 품질 미측정")}</p>}
          </section>
          <section className="card p-4 text-sm">
            <h2 className="mb-2 font-semibold">{L(lang, "M1 독립 실행")}</h2>
            <pre className="mono whitespace-pre-wrap rounded bg-[#f3f4f8] p-2">{`aegis run ${a.id} --input request.json
aegis serve ${a.id} --protocol rest --port 8080
aegis serve ${a.id} --protocol mcp --stdio`}</pre>
          </section>
        </aside>
      </div>
      {cfg && (
        <section className="card mt-4 p-4" id="settings">
          <h2 className="mb-2 font-semibold">{tr(lang, "조직 설정 (정책 agentParams)", "Organization settings (policy agentParams)")}</h2>
          <AgentSettings cfg={cfg} editable={can(user, "policy.write")} />
        </section>
      )}
    </>
  );
}
