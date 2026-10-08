// SCR-N04 증적 원장 탐색·무결성 검증 — 추가 전용, 수정·삭제 버튼 없음(MSG-016).
import Link from "next/link";
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime, shortHash } from "@/lib/format";
import { t, tr, LX } from "@/lib/i18n";
import { prefs } from "@/lib/session";

import { L, type Lang } from "@/lib/i18n";

function summary(r: any, lang: Lang): string {
  const b = r.body;
  switch (r.kind) {
    case "finding": return `${b.agent?.id} ${b.verdict}${b.effectiveVerdict && b.effectiveVerdict !== b.verdict ? `→${b.effectiveVerdict}` : ""} ${b.ruleId}`;
    case "gate": return L(lang, "{0} {1} · {2}종 · {3}ms{4}", b.gate, b.verdict, b.agents?.length, b.latencyMs, b.degraded?.length ? L(lang, " · 강등 {0}", b.degraded.join(",")) : "");
    case "approval": return `${b.event} ${b.by ?? b.requestedBy ?? ""} ${b.decision ?? ""} ${b.status ?? ""}`;
    case "profile": return `${b.event} ${b.profile ?? ""} ${b.stage ?? ""} by ${b.by}`;
    case "policy": return `${b.event} by ${b.by}`;
    case "export": return L(lang, "export {0}건 by {1}", b.records, b.by);
    case "scan": return b.event ? `${b.event} ${b.kind ?? ""} ${b.name ?? ""}` : `${b.kind} ${b.name ?? ""} → ${b.verdict}${b.quarantine ? L(lang, " · 격리 {0}", b.quarantine) : ""} (${b.hits?.length ?? 0} hits)`;
    case "quarantine": return `${b.event} ${b.kind ?? ""} ${b.value ?? ""} by ${b.by}`;
    case "incident": return `${b.event} ${b.domain ?? ""} ${b.severity ?? ""} ${b.actor ?? b.by ?? ""}`;
    case "redteam": return L(lang, "campaign {0}종 · 회귀 {1} by {2}", b.agents, b.regressions?.length ?? 0, b.by);
    case "risk": return `${b.event} ${b.id ?? ""} ${b.decision ?? ""} by ${b.by}`;
    case "report": return `${b.event} ${JSON.stringify(b.summary)}`;
    case "governance": return `${b.event} ${b.verdict} · ${b.hits?.length ?? 0} hits`;
    case "agent": return `${b.event} ${b.outcome ?? ""} ${b.name ?? ""} by ${b.by ?? ""}`;
    default: return JSON.stringify(b).slice(0, 80);
  }
}

export default async function Evidence({ searchParams }: { searchParams: Promise<{ kind?: string; before?: string; check?: string }> }) {
  const { lang } = await prefs();
  const sp = await searchParams;
  const q = new URLSearchParams({ limit: "100", ...(sp.kind ? { kind: sp.kind } : {}), ...(sp.before ? { before: sp.before } : {}) });
  const [recs, ver, key] = await Promise.all([
    safe(api(`/v1/evidence?${q}`), { items: [] as any[] }),
    sp.check ? safe(api("/v1/evidence:verify"), null as any) : Promise.resolve({ data: null as any, error: undefined }),
    safe(api("/v1/evidence/public-key"), null as any),
  ]);
  const last = recs.data.items.at(-1);
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupGov")} › ${t(lang, "evidence")}`} title={tr(lang, "증적 원장 — 추가 전용", "Evidence ledger — append-only")}
        actions={<><a href="/evidence/retention" className="btn btn-secondary">{tr(lang, "보존기한 만료", "Retention expiry")}</a><a href="/evidence/export" className="btn btn-primary">{t(lang, "export")} &gt;</a></>} />
      <form className="mb-3 flex gap-2 text-sm">
        <select name="kind" defaultValue={sp.kind ?? ""} className="input" aria-label="kind">
          <option value="">{L(lang, "유형: 전체")}</option>
          {["finding", "gate", "approval", "profile", "policy", "agent", "export", "scan", "quarantine", "incident", "redteam", "risk", "report", "governance"].map((k) => <option key={k}>{k}</option>)}
        </select>
        <button className="btn btn-primary">{L(lang, "질의")}</button>
      </form>
      <div className="grid grid-cols-[1fr_320px] gap-4">
        <div>
          <div className="card overflow-hidden">
            <table className="grid-table">
              <thead><tr><th>seq</th><th>{L(lang, "시각")}</th><th>{L(lang, "유형")}</th><th>{L(lang, "내용")}</th><th>{L(lang, "참조")}</th><th>{L(lang, "레코드 해시")}</th></tr></thead>
              <tbody>
                {recs.data.items.map((r: any) => (
                  <tr key={r.seq}>
                    <td className="mono">{r.seq}</td><td className="text-xs">{fmtTime(r.createdAt)}</td><td><Chip>{LX(lang, r.kind)}</Chip></td>
                    <td className="text-xs">{summary(r, lang)}</td>
                    <td className="mono text-xs">{r.kind === "finding" ? <Link className="text-primary" href={`/findings/${r.refId}`}>{shortHash(r.refId, 12)}</Link> : shortHash(r.refId, 12)}</td>
                    <td className="mono text-xs" title={`prev ${r.prevHash}`}>{shortHash(r.hash)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-3"><Banner tone="info">{t(lang, "appendOnly")}</Banner></div>
          {last && last.seq > 1 && <Link className="mt-2 inline-block text-sm text-primary" href={`/evidence?before=${last.seq}${sp.kind ? `&kind=${sp.kind}` : ""}`}>{L(lang, "이전 레코드 ›")}</Link>}
        </div>
        <aside className="space-y-4">
          <section className="card p-4 text-sm" style={{ borderColor: "var(--primary)" }}>
            <h2 className="mb-2 font-semibold">{t(lang, "verify")}</h2>
            {ver.data ? (
              <>
                <ul className="space-y-1">
                  <li>{ver.data.ok ? "● " : "✗ "}{L(lang, "해시 체인 — ")}{LX(lang, ver.data.detail)}</li>
                  <li>{L(lang, "● 체크포인트 서명 ")}{ver.data.badCheckpoints.length ? L(lang, "불일치 {0}", ver.data.badCheckpoints.join(",")) : L(lang, "정상")}</li>
                </ul>
                <dl className="mt-2 grid grid-cols-2 gap-y-1 text-xs">
                  <dt className="text-muted">{L(lang, "레코드")}</dt><dd>{ver.data.records.toLocaleString()}</dd>
                  <dt className="text-muted">{L(lang, "체크포인트")}</dt><dd>{LX(lang, ver.data.checkpoints)}</dd>
                  <dt className="text-muted">{L(lang, "머리")}</dt><dd className="mono">#{ver.data.head?.seq} {shortHash(ver.data.head?.hash)}</dd>
                </dl>
                {!ver.data.ok && <div className="mt-2"><Banner tone="danger">{L(lang, "불일치 발견 — 사건 생성·알림 (MSG-017)")}</Banner></div>}
              </>
            ) : <p className="text-muted">{L(lang, "전체 체인 재계산은 비용이 크므로 요청 시에만 실행한다.")}</p>}
            <Link href="/evidence?check=1" className="btn btn-primary mt-3 w-full justify-center">{L(lang, "전 구간 검증 실행")}</Link>
          </section>
          <section className="card p-4 text-xs">
            <div className="font-semibold">{L(lang, "서명 공개키 (Ed25519)")}</div>
            <div className="mono mt-1 break-all">keyId {LX(lang, key.data?.keyId)}</div>
            <div className="mono break-all text-muted">{LX(lang, key.data?.publicKey)}</div>
            <p className="mt-2">{L(lang, "독립 검증: ")}<span className="mono">python -m aegis verify-bundle bundle.json</span></p>
          </section>
        </aside>
      </div>
    </>
  );
}
