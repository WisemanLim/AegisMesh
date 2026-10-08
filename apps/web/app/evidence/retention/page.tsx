// 증적 보존기한 만료 (원본 PRD NFR-S · R07) — 삭제 API 는 없고, 서명 체크포인트까지·법적 보존 앞까지만 2인 승인 배치로 지운다. 서명 삭제 증명.
import Link from "next/link";
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime, shortHash } from "@/lib/format";
import { t as tk, tr } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { requestPurge } from "./actions";

export default async function Retention({ searchParams }: { searchParams: Promise<{ msg?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const { msg } = await searchParams;
  const { data, error } = await safe(api("/v1/evidence/retention"), null as any);
  const priv = can(user, "privacy");
  return (
    <>
      <PageHeader crumb={`${tk(lang, "groupGov")} › ${tk(lang, "evidence")} › ${tr(lang, "보존기한 만료", "Retention expiry")}`}
        title={tr(lang, "보존기한 만료 · 삭제 증명", "Retention expiry · deletion certificates")} actions={<Link className="btn btn-secondary" href="/evidence">‹ {tk(lang, "evidence")}</Link>} />
      {msg && <div className="mb-3"><Banner tone={/^(실패|Failed)/.test(msg) ? "danger" : "info"}>{msg}</Banner></div>}
      {error && <p className="text-sm text-red-600">{error}</p>}
      <div className="mb-3"><Banner tone="info">{tr(lang, "원장에는 삭제 API 가 없다 — 보존기한이 지난 앞부분만, 서명 체크포인트까지·법적 보존 기록 앞까지, 2인 승인 뒤 배치로 지운다. 지운 구간은 서명 증명서와 체인 안 기록으로 남고, 검증은 앵커에서 이어진다.",
        "The ledger has no delete API — only the expired head, up to a signed checkpoint and before any legal-hold record, is removed by a batch after two approvals. Each purge leaves a signed certificate and an in-chain record; verification resumes from the anchor.")}</Banner></div>
      <section className="card overflow-hidden text-sm" data-testid="retention-plans">
        <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "체인", "Chain")}</th><th>{tr(lang, "보존", "Retention")}</th><th>{tr(lang, "기준일", "Cutoff")}</th><th>{tr(lang, "기록", "Records")}</th><th>{tr(lang, "만료 대상", "Due")}</th><th>{tr(lang, "법적 보존", "Legal hold")}</th><th>{tr(lang, "마지막 삭제", "Last purge")}</th><th /></tr></thead>
          <tbody>{(data?.items ?? []).map((p: any) => (
            <tr key={p.chain} data-chain={p.chain}><td className="mono">{p.chain}</td><td>{p.retentionDays ?? "—"}{p.retentionDays ? tr(lang, "일", " d") : ""}</td><td>{p.cutoff ? fmtTime(p.cutoff) : "—"}</td><td>{p.records ?? "—"}</td>
              <td>{p.eligible ? <b>{tr(lang, `seq ${p.fromSeq}~${p.throughSeq} · ${p.purge}건`, `seq ${p.fromSeq}–${p.throughSeq} · ${p.purge}`)}</b> : <span className="text-muted">{p.reason ? tr(lang, p.reason, p.reason.includes("법적") ? "no expired checkpoint before the legal hold" : p.reason.includes("legacy") ? "legacy chain is frozen" : "no expired signed checkpoint") : "—"}</span>}</td>
              <td>{p.legalHold?.minSeq ? <span>seq ≥ {p.legalHold.minSeq} · {p.legalHold.incidents.map((i: string) => <Link key={i} className="text-primary" href={`/incidents/${i}`}>{i} </Link>)}</span> : "—"}</td>
              <td>{p.lastPurge ? `${fmtTime(p.lastPurge.createdAt)} · ≤ ${p.lastPurge.throughSeq}` : "—"}</td>
              <td>{priv && p.eligible && <form action={requestPurge}><input type="hidden" name="chain" value={p.chain} /><button className="btn btn-secondary h-6 text-xs">{tr(lang, "만료 요청 (2인)", "Request (2 approvals)")}</button></form>}</td></tr>))}</tbody></table>
      </section>
      <section className="card mt-4 overflow-hidden text-sm" data-testid="purges">
        <h2 className="p-3 font-semibold">{tr(lang, "삭제 증명서", "Deletion certificates")}</h2>
        <table className="grid-table text-xs"><thead><tr><th>ID</th><th>{tr(lang, "체인", "Chain")}</th><th>{tr(lang, "구간", "Range")}</th><th>{tr(lang, "건수", "Records")}</th><th>{tr(lang, "앵커", "Anchor")}</th><th>{tr(lang, "승인", "Approvers")}</th><th>{tr(lang, "서명", "Signature")}</th><th /></tr></thead>
          <tbody>{(data?.purges ?? []).length === 0 ? <tr><td colSpan={8} className="text-muted">{tr(lang, "아직 없음", "None yet")}</td></tr> : data.purges.map((g: any) => (
            <tr key={g.id}><td className="mono">{g.id}</td><td>{g.chain}</td><td>{g.certificate.fromSeq}~{g.throughSeq}</td><td>{g.records}</td><td className="mono">{shortHash(g.anchorHash, 12)}</td>
              <td>{(g.certificate.approvers ?? []).join(", ")}</td><td>{g.signatureOk ? <Chip tone="primary">{tr(lang, "검증 ✓", "valid ✓")}</Chip> : <b style={{ color: "var(--verdict-block)" }}>✗</b>}</td>
              <td><a className="text-primary" href={`/evidence/retention/certificate?id=${encodeURIComponent(g.id)}`}>{tr(lang, "증명서 ↓", "Certificate ↓")}</a></td></tr>))}</tbody></table>
      </section>
      <p className="mt-2 text-xs text-muted">{tr(lang, "worker 가 매일 만료 대상을 찾아 승인 요청을 낸다. 포렌식 보존(법적 보존) 기록과 그 묶음이 가리키는 기록은 지우지 않는다.", "The worker files approval requests daily. Forensic (legal-hold) records and the records their bundles reference are never purged.")}</p>
    </>
  );
}
