// SCR-R01 테넌트 관리 — 정책 네임스페이스·증적 체인·캐시 접두, 교차 접근 차단 시험(매일 자동 + 지금 시험).
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { t, tr, LX } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { addTenant, runIsolationTest, setTenantActive } from "../actions";

import { L } from "@/lib/i18n";

export default async function Tenants({ searchParams }: { searchParams: Promise<{ msg?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const { msg } = await searchParams;
  const admin = can(user, "tenant.admin");
  const [list, last] = await Promise.all([
    safe(api("/v1/tenants"), { items: [] as any[] }),
    admin ? safe(api("/v1/tenants/isolation-test"), {} as any) : Promise.resolve({ data: {} as any }),
  ]);
  const test = last.data;
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupAdmin")} › ${t(lang, "tenants")}`} title={tr(lang, "테넌트 관리", "Tenants")} />
      {msg && <div className="mb-3"><Banner tone={msg.startsWith(L(lang, "실패")) ? "danger" : "info"}>{L(lang, msg)}</Banner></div>}
      <div className="grid grid-cols-[1fr_360px] gap-4">
        <div className="space-y-4">
          <div className="card overflow-hidden">
            <table className="grid-table">
              <thead><tr><th>{L(lang, "테넌트")}</th><th>{L(lang, "분리 방식")}</th><th>{L(lang, "정책 NS")}</th><th>{L(lang, "증적 파티션")}</th><th>{L(lang, "캐시 접두")}</th><th>{L(lang, "프로파일")}</th><th>{L(lang, "사용자")}</th><th>{L(lang, "상태")}</th></tr></thead>
              <tbody>
                {list.data.items.map((x: any) => (
                  <tr key={x.id}>
                    <td><b className="mono">{x.id}</b> · {LX(lang, x.name)}</td>
                    <td><Chip tone="primary">{x.isolation === "logical" ? L(lang, "논리 분리") : L(lang, "물리 분리")}</Chip></td>
                    <td className="mono text-xs">{LX(lang, x.namespaces.policy)}</td>
                    <td className="mono text-xs">{LX(lang, x.namespaces.ledger)} · {LX(lang, x.ledger.records)}{L(lang, "건 ")}{x.ledger.head ? `(${x.ledger.head}…)` : ""}</td>
                    <td className="mono text-xs">{LX(lang, x.namespaces.cachePrefix)}</td>
                    <td>{LX(lang, x.profile ?? "—")}</td>
                    <td>{LX(lang, x.users)}</td>
                    <td>
                      {admin && x.id !== "default" ? (
                        <form action={setTenantActive} className="inline">
                          <input type="hidden" name="id" value={x.id} />
                          <input type="hidden" name="active" value={String(!x.active)} />
                          <button className="btn btn-secondary h-7 text-xs">{x.active ? L(lang, "정상 · 비활성화") : L(lang, "비활성 · 활성화")}</button>
                        </form>
                      ) : (x.active ? L(lang, "정상") : L(lang, "비활성"))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Banner tone="info">{L(lang, "모든 캐시 키·검색 인덱스 네임스페이스·원장 레코드에 테넌트 식별자 포함 · 테넌트 간 정책·증적 공유 없음 · 보존 ")}{LX(lang, list.data.items[0]?.retentionDays ?? 90)}{L(lang, "일(기본). 물리 분리(전용 원장·키·샌드박스 풀)는 전용 설치가 필요하다.")}</Banner>
          {admin && (
            <section className="card p-4 text-sm">
              <div className="mb-2 flex items-center justify-between">
                <h2 className="font-semibold">{L(lang, "교차 접근 차단 시험 ")}<span className="text-xs font-normal text-muted">{L(lang, "매일 자동(worker) · 위반 시 사건")}</span></h2>
                <form action={runIsolationTest}><button className="btn btn-primary h-8 text-xs">{L(lang, "지금 시험")}</button></form>
              </div>
              {test?.checks ? (
                <>
                  <p className="mb-2 text-xs text-muted">{L(lang, "마지막 실행 ")}{fmtTime(test.at)} · {LX(lang, test.by)} · {LX(lang, test.passed)}/{test.total} {test.ok ? L(lang, "통과") : L(lang, "실패")}{L(lang, " · 대상 ")}{test.tenants.join(", ")}</p>
                  <ul className="space-y-1">
                    {test.checks.map((c: any) => (
                      <li key={c.id} className="flex gap-2"><span style={{ color: c.ok ? "var(--verdict-allow)" : "var(--verdict-block)" }}>{c.ok ? "✓" : "✗"}</span>
                        <span>{LX(lang, c.title)}</span><span className="ml-auto text-xs text-muted">{LX(lang, c.detail)}</span></li>
                    ))}
                  </ul>
                </>
              ) : <p className="text-muted">{L(lang, "아직 실행 기록 없음")}</p>}
            </section>
          )}
        </div>
        {admin ? (
          <form action={addTenant} className="card h-fit space-y-2 p-4 text-sm">
            <h2 className="font-semibold">{L(lang, "+ 테넌트 추가")}</h2>
            <input name="id" required pattern="[a-z][a-z0-9\-]{1,31}" placeholder={L(lang, "테넌트 ID (예: garam)")} className="input mono w-full" aria-label="tenant id" />
            <input name="name" required placeholder={L(lang, "표시 이름")} className="input w-full" aria-label="tenant name" />
            <label className="block text-xs text-muted">{L(lang, "증적 보존(일)")}<input name="retention" type="number" min={1} max={3650} defaultValue={90} className="input mt-1 w-full" />
            </label>
            <select name="lang" className="input w-full" aria-label="language" defaultValue="ko"><option value="ko">{L(lang, "보고서 한국어")}</option><option value="en">English</option></select>
            <button className="btn btn-primary w-full justify-center">{L(lang, "생성 (정책 v1 · 원장 체인 준비)")}</button>
            <p className="text-xs text-muted">{L(lang, "생성은 원장(플랫폼·테넌트 체인)에 기록된다.")}</p>
          </form>
        ) : <div className="card h-fit p-4 text-sm text-muted">{t(lang, "readOnly")}</div>}
      </div>
    </>
  );
}
