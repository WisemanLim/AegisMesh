// SCR-A05 폐쇄망 번들 반입·서명 검증 · SCR-R05 업데이트·폐쇄망·신뢰 저장소.
import Link from "next/link";
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime, shortHash } from "@/lib/format";
import { t, tr, LX } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { addTrustKey, importBundle, revokeTrustKey } from "../actions";

import { L } from "@/lib/i18n";

const STEPS = [["signature", "서명"], ["hash", "해시"], ["sbom", "SBOM·취약점"], ["apply", "적용"]];

export default async function Airgap({ searchParams }: { searchParams: Promise<{ msg?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const { msg } = await searchParams;
  const admin = can(user, "tenant.admin");
  const [keys, imps, sb] = await Promise.all([
    safe(api("/v1/trust-keys"), { items: [] as any[] }), safe(api("/v1/airgap/imports"), { items: [] as any[] }), safe(api("/v1/sbom"), null as any),
  ]);
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupAdmin")} › ${t(lang, "airgap")}`} title={tr(lang, "업데이트 · 폐쇄망 · 신뢰 저장소", "Updates · air-gap · trust store")} />
      {msg && <div className="mb-3"><Banner tone={msg.startsWith(L(lang, "실패")) ? "danger" : "info"}>{L(lang, msg)}</Banner></div>}
      <div className="mb-3 flex gap-2 text-xs"><Chip tone="primary">{L(lang, "외부 조회 없음 — 반입 경로만 활성 (MSG-029)")}</Chip><Chip>{L(lang, "서명 검증 = 내부 신뢰 저장소")}</Chip><Chip>{L(lang, "SBOM 기준 critical 0 · high ≤ 3")}</Chip></div>
      <div className="grid grid-cols-[1fr_380px] gap-4">
        <section className="card p-4 text-sm" data-testid="imports">
          <h2 className="mb-2 font-semibold">{L(lang, "번들 반입 기록 — 단계: 서명 → 해시 → SBOM·취약점 → 적용 (하나라도 실패하면 중단)")}</h2>
          <table className="grid-table text-xs"><thead><tr><th>{L(lang, "반입")}</th><th>{L(lang, "버전")}</th><th>{L(lang, "키")}</th>{STEPS.map(([k, l]) => <th key={k}>{L(lang, l)}</th>)}<th>{L(lang, "적용")}</th><th>{L(lang, "시각")}</th></tr></thead>
            <tbody>{imps.data.items.length === 0 ? <tr><td colSpan={9} className="text-muted">{t(lang, "noData")}</td></tr> : imps.data.items.map((i: any) => {
              const by = Object.fromEntries(i.steps.map((s: any) => [s.step, s]));
              return (
                <tr key={i.id}><td className="mono">{i.id} <span className="text-muted">{shortHash(i.sha256)}</span></td><td>{LX(lang, i.version ?? "—")}</td><td className="mono">{LX(lang, i.keyId ?? "—")}</td>
                  {STEPS.map(([k]) => <td key={k} title={by[k]?.detail}>{by[k] ? (by[k].ok ? "✓" : <b style={{ color: "var(--verdict-block)" }}>✗</b>) : "·"}</td>)}
                  <td className="max-w-[260px] text-[11px]">{i.status === "imported" ? i.steps.at(-1)?.detail : <span style={{ color: "var(--verdict-block)" }}>{LX(lang, i.steps.find((s: any) => !s.ok)?.detail)}</span>}</td>
                  <td>{fmtTime(i.createdAt)}</td></tr>
              );
            })}</tbody></table>
          {admin && (
            <form action={importBundle} className="mt-3 flex items-center gap-2">
              <input type="file" name="bundle" accept=".tar.gz,.tgz,application/gzip" className="input text-xs" aria-label="bundle file" />
              <button className="btn btn-primary h-8 text-xs">{L(lang, "반입 (검증 후 적용)")}</button>
              <span className="text-xs text-muted">{L(lang, "USB·망연계 매체의 ")}<code className="mono">aegis airgap build</code>{L(lang, " 산출물 · 사전 오프라인 검증 ")}<code className="mono">aegis airgap verify</code></span>
            </form>
          )}
        </section>
        <section className="card p-4 text-sm">
          <h2 className="mb-2 font-semibold">{L(lang, "내부 신뢰 저장소 (추가·폐기 2인 승인)")}</h2>
          <ul className="space-y-1 text-xs">{keys.data.items.map((k: any) => (
            <li key={k.keyId} className="flex items-center justify-between gap-2">
              <span><b className="mono">{LX(lang, k.keyId)}</b> {LX(lang, k.name)} <Chip tone={k.status === "active" ? "primary" : undefined}>{LX(lang, k.status)}</Chip>{k.status === "pending" && <Link className="ml-1 text-primary" href="/approvals">{L(lang, "승인함")}</Link>}</span>
              {admin && k.status === "active" && <form action={revokeTrustKey}><input type="hidden" name="keyId" value={k.keyId} /><button className="btn btn-secondary h-6 text-xs">{L(lang, "폐기 요청")}</button></form>}
            </li>
          ))}</ul>
          {admin && (
            <form action={addTrustKey} className="mt-3 space-y-1">
              <input name="keyId" required placeholder={L(lang, "keyId (예: rel-2026)")} className="input w-full text-xs" aria-label="trust key id" />
              <input name="name" required placeholder={L(lang, "이름")} className="input w-full text-xs" aria-label="trust key name" />
              <input name="publicKey" required placeholder={L(lang, "base64 Ed25519 공개키")} className="input mono w-full text-xs" aria-label="trust public key" />
              <button className="btn btn-secondary w-full justify-center text-xs">{L(lang, "키 등록 요청")}</button>
            </form>
          )}
          <h2 className="mb-1 mt-4 font-semibold">{L(lang, "자체 릴리스 SBOM")}</h2>
          {sb.data ? (
            <p className="text-xs">CycloneDX {LX(lang, sb.data.sbom.specVersion)}{L(lang, " · 구성요소 ")}{sb.data.sbom.components.length}{L(lang, " · 취약점 DB ")}{LX(lang, sb.data.vulndb)}{L(lang, " · 대조 ")}{JSON.stringify(sb.data.vulnGate.counts)} {sb.data.vulnGate.ok ? "✓" : "✗"} · <a className="text-primary" href="/admin/airgap/sbom">{L(lang, "내려받기")}</a></p>
          ) : <p className="text-xs text-muted">—</p>}
        </section>
      </div>
    </>
  );
}
