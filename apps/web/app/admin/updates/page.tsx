// SCR-R05 업데이트 — 구성요소·에이전트 버전, 에이전트별 롤링 교체(품질 게이트 실패 시 자동 롤백), 반입·교체 이력, 자체 릴리스 SBOM·서명. 폐쇄망 반입·신뢰 저장소는 /admin/airgap.
import Link from "next/link";
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime, shortHash } from "@/lib/format";
import { t as tk, tr, nm } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { reloadAgent } from "./actions";

const EV: Record<string, [string, string]> = { agent_reloaded: ["교체 완료", "Replaced"], agent_rollback: ["롤백됨", "Rolled back"], bundle_imported: ["번들 반입", "Bundle imported"],
  bundle_rejected: ["반입 거부", "Bundle rejected"], bundle_applied: ["번들 적용", "Bundle applied"] };

export default async function Updates({ searchParams }: { searchParams: Promise<{ msg?: string; q?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const { msg, q } = await searchParams;
  const pub = can(user, "publisher");
  const [u, sb, keys] = await Promise.all([
    safe(api("/v1/updates"), null as any), safe(api("/v1/updates/sbom"), null as any), safe(api("/v1/trust-keys"), { items: [] as any[] }),
  ]);
  const d = u.data;
  const agents = (d?.agents ?? []).filter((a: any) => !q || a.id.includes(q) || (a.name ?? "").toLowerCase().includes(q.toLowerCase()));
  return (
    <>
      <PageHeader crumb={`${tk(lang, "groupAdmin")} › ${tk(lang, "updates")}`} title={tr(lang, "업데이트 · 롤링 교체 · 자체 SBOM", "Updates · rolling replacement · release SBOM")}
        actions={<Link className="btn btn-secondary" href="/admin/airgap">{tr(lang, "폐쇄망 번들 반입 · 신뢰 저장소 ›", "Air-gap bundle import · trust store ›")}</Link>} />
      {msg && <div className="mb-3"><Banner tone={/^(실패|Failed)/.test(msg) || /롤백|rolled back/.test(msg) ? "danger" : "info"}>{msg}</Banner></div>}
      {u.error && <p className="mb-3 text-sm text-red-600">{u.error}</p>}
      <div className="mb-3 flex flex-wrap gap-2 text-xs" data-testid="update-status">
        <Chip tone="primary">{tr(lang, `플랫폼 ${d?.platform ?? "—"}`, `Platform ${d?.platform ?? "—"}`)}</Chip>
        <Chip>{tr(lang, `에이전트 ${d?.agents.length ?? 0}종`, `${d?.agents.length ?? 0} agents`)}</Chip>
        <Chip>{tr(lang, "폐쇄망 — 외부 조회 없음, 번들 반입 경로만 (MSG-029)", "Air-gapped — no online checks, bundle import only (MSG-029)")}</Chip>
        <Chip>{tr(lang, `신뢰 저장소 키 ${keys.data.items.filter((k: any) => k.status === "active").length}개`, `${keys.data.items.filter((k: any) => k.status === "active").length} trust keys`)}</Chip>
      </div>
      <div className="grid grid-cols-[1fr_400px] gap-4">
        <section className="card overflow-hidden text-sm" data-testid="versions">
          <div className="flex items-center gap-2 p-3">
            <h2 className="font-semibold">{tr(lang, "버전 · 롤링 교체", "Versions · rolling replacement")}</h2>
            <form className="ml-auto"><input name="q" defaultValue={q ?? ""} placeholder={tr(lang, "에이전트 검색", "Search agents")} className="input h-7 w-48 text-xs" aria-label="search agents" /></form>
          </div>
          <p className="px-3 pb-2 text-xs text-muted">{tr(lang, "에이전트별 교체 — 품질 게이트(골든·공격 재생) 통과 시에만 새 인스턴스로, 실패하면 기존 인스턴스 유지(자동 롤백). 관문 재기동 없음 (ST-12)", "Per-agent replacement — new instance only if the quality gate (golden + attack replay) passes; otherwise the old one stays (auto rollback). No gate restart (ST-12)")}</p>
          <div tabIndex={0} className="max-h-[560px] overflow-auto">
            <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "구성요소", "Component")}</th><th>{tr(lang, "버전", "Version")}</th><th>{tr(lang, "출처", "Origin")}</th><th>{tr(lang, "상태", "Status")}</th><th>{tr(lang, "갱신", "Updated")}</th><th /></tr></thead>
              <tbody>
                <tr><td><b>{tr(lang, "관문 게이트웨이 · 콘솔 API", "Gate gateway · console API")}</b></td><td className="mono">{d?.platform}</td><td>platform</td><td>{tr(lang, "운영", "running")}</td><td>—</td><td /></tr>
                {agents.map((a: any) => (
                  <tr key={a.id}><td><Link className="mono text-primary" href={`/catalog/${a.id}`}>{a.id}</Link> <span className="text-muted">{nm(lang, a)}</span></td><td className="mono">{a.version}</td><td>{a.origin}</td><td>{a.status}</td><td>{fmtTime(a.updatedAt)}</td>
                    <td>{pub && <form action={reloadAgent}><input type="hidden" name="id" value={a.id} /><button className="btn btn-secondary h-6 text-xs" data-testid={`reload-${a.id}`}>{tr(lang, "교체", "Replace")}</button></form>}</td></tr>))}
              </tbody></table>
          </div>
        </section>
        <div className="space-y-4">
          <section className="card p-4 text-sm" data-testid="pins">
            <h2 className="mb-2 font-semibold">{tr(lang, "고정 판 — 이미지에 구운 외부 참조 데이터", "Pinned snapshots — reference data baked into the image")}</h2>
            <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "데이터", "Data")}</th><th>{tr(lang, "판", "Snapshot")}</th><th>{tr(lang, "기준", "Freshness")}</th><th>{tr(lang, "상태", "Status")}</th></tr></thead>
              <tbody>{(d?.pins?.items ?? []).map((p: any) => (
                <tr key={p.name}><td className="mono">{p.name === "fido-mds3" ? "FIDO MDS3" : "DB-IP City Lite"}</td><td className="mono">{p.version ?? "—"}</td>
                  <td>{p.name === "fido-mds3" ? tr(lang, `다음 갱신 ${p.nextUpdate ?? "—"}`, `next update ${p.nextUpdate ?? "—"}`) : tr(lang, `빌드 ${p.built ?? "—"} · ${p.ageDays ?? "—"}일`, `built ${p.built ?? "—"} · ${p.ageDays ?? "—"} days`)}</td>
                  <td>{p.stale ? <Chip>⚠ {tr(lang, "낡음", "stale")}</Chip> : <Chip tone="primary">{tr(lang, "최신", "current")}</Chip>}</td></tr>))}</tbody></table>
            <p className="mt-2 text-xs text-muted">{tr(lang, "갱신 = `make pins-refresh`(이미지 빌드 안에서 다음 판 확인 → Dockerfile 고정값) → 재빌드. 실행 중 네트워크 없음 · 낡으면 매일 알림", "Refresh = `make pins-refresh` (the next snapshot is resolved inside an image build → Dockerfile pins) → rebuild. No network at run time · daily alert when stale")}</p>
          </section>
          <section className="card p-4 text-sm" data-testid="release-sbom">
            <h2 className="mb-2 font-semibold">{tr(lang, "자체 릴리스 SBOM · 서명", "Release SBOM · signature")}</h2>
            {sb.data ? (
              <table className="grid-table text-xs"><tbody>
                <tr><td className="w-44 text-muted">SBOM</td><td>CycloneDX {sb.data.sbom.specVersion} · {tr(lang, `구성요소 ${sb.data.sbom.components.length}개`, `${sb.data.sbom.components.length} components`)}</td></tr>
                <tr><td className="w-44 text-muted">{tr(lang, "서명", "Signature")}</td><td className="mono">{sb.data.signature.alg} · kid {sb.data.signature.kid}</td></tr>
                <tr><td className="w-44 text-muted">sha256</td><td className="mono">{shortHash(sb.data.signature.sha256, 16)}</td></tr>
                <tr><td className="w-44 text-muted">{tr(lang, "취약점 대조", "Vulnerability gate")}</td><td>{JSON.stringify(sb.data.vulnGate.counts)} {sb.data.vulnGate.ok ? "✓" : "✗"}</td></tr>
                <tr><td className="w-44 text-muted">{tr(lang, "검증", "Verify")}</td><td className="text-[11px]">JWKS <code className="mono">/v1/identity/jwks</code> · {tr(lang, "정렬 JSON 바이트에 대한 Ed25519", "Ed25519 over sorted-JSON bytes")}</td></tr>
              </tbody></table>) : <p className="text-xs text-muted">{sb.error ?? "—"}</p>}
            <a className="btn btn-secondary mt-2 h-7 text-xs" href="/admin/updates/sbom" data-testid="sbom-download">{tr(lang, "SBOM + 서명 내려받기", "Download SBOM + signature")}</a>
          </section>
          <section className="card p-4 text-sm" data-testid="history">
            <h2 className="mb-2 font-semibold">{tr(lang, "반입 · 교체 이력", "Import · replacement history")}</h2>
            <ul className="space-y-1 text-xs">{(d?.history ?? []).length === 0 ? <li className="text-muted">—</li> : d.history.slice(0, 15).map((h: any) => (
              <li key={h.seq}><b style={{ color: /rollback|rejected/.test(h.event) ? "var(--verdict-block)" : undefined }}>{tr(lang, ...(EV[h.event] ?? [h.event, h.event]))}</b> {h.agent ?? h.version ?? ""} <span className="text-muted">· {fmtTime(h.at)}</span>
                {h.detail && <div className="text-muted">{String(h.detail).slice(0, 140)}</div>}</li>))}</ul>
          </section>
        </div>
      </div>
    </>
  );
}
