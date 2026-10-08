// SCR-E02 입력 검사 뷰어 — 입력 관문 판정 하나를 근거 중심으로 해부: 세그먼트 출처·신뢰·지시 권한(스포트라이팅), 근거 구간,
// 같은 trace 의 다른 에이전트 판정. 원문은 저장돼 있지 않다(MSG-024) — 원문 재검사는 붙여 넣은 입력으로(저장 없음).
import Link from "next/link";
import { notFound } from "next/navigation";
import { Banner, Chip, SeverityBadge, VerdictBadge } from "@/components/Badges";
import { Inspector } from "@/components/Inspector";
import { PageHeader } from "@/components/Shell";
import { ApiError, api } from "@/lib/api";
import { fmtTime, shortHash } from "@/lib/format";
import { tr, LX } from "@/lib/i18n";
import { prefs } from "@/lib/session";

export default async function InspectFinding({ params }: { params: Promise<{ d: string; fid: string }> }) {
  const { lang } = await prefs();
  const { fid } = await params;
  let x: any;
  try {
    x = await api(`/v1/findings/${fid}/inspect`);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound();
    throw e;
  }
  const f = x.finding;
  const skeleton = { text: "", segments: (x.shape.segments ?? []).map((g: any) => ({ source: g.source, trust: g.trust, text: "" })) };
  return (
    <>
      <PageHeader crumb={`${tr(lang, "위험 영역", "Risk domains")} › D1 › ${tr(lang, "입력 검사", "Input inspection")}`} title={tr(lang, `입력 검사 뷰어 — ${f.id}`, `Input inspection viewer — ${f.id}`)} />
      <div className="mb-3 flex flex-wrap items-center gap-2 text-sm" data-testid="inspect-head">
        <VerdictBadge v={f.effective ?? f.verdict} /><SeverityBadge s={f.severity} /><Chip tone="primary">{f.agent}</Chip><span className="mono">{f.ruleId}</span>
        <span>conf {f.confidence}</span><span className="mono">trace <Link className="text-primary" href={`/findings?trace=${f.traceId}`}>{shortHash(f.traceId)}</Link></span>
        <span>{f.principal ?? "—"}</span><span className="text-muted">{fmtTime(f.at)}</span>
        {!f.valid && <b style={{ color: "var(--verdict-block)" }}>{tr(lang, "무효 판정(근거 없음)", "Invalid (no evidence)")}</b>}
        {f.effective && f.effective !== f.verdict && <span className="text-xs text-muted">{tr(lang, `원판정 ${f.verdict} → 정책 ${f.effective}`, `raw ${f.verdict} → policy ${f.effective}`)}</span>}
      </div>
      <div className="mb-3"><Banner tone="info">{tr(lang, "원문 미보존(기본) — 근거 구간(위치·길이)과 요청 모양(세그먼트 출처·신뢰·길이)만 표시. 사용자에게는 참조 ID 만 노출(MSG-024).",
        "Raw text not retained (default) — only evidence spans (location · length) and request shape (segment source · trust · length). Users only see a reference ID (MSG-024).")}</Banner></div>
      <div className="grid grid-cols-2 gap-4">
        <section className="card overflow-hidden text-sm" data-testid="inspect-segments">
          <h2 className="p-3 font-semibold">{tr(lang, "컨텍스트 세그먼트 · 출처 신뢰", "Context segments · source trust")}</h2>
          <table className="grid-table text-xs"><thead><tr><th>#</th><th>{tr(lang, "출처", "Source")}</th><th>{tr(lang, "신뢰", "Trust")}</th><th>{tr(lang, "권한", "Authority")}</th><th>{tr(lang, "글자", "Chars")}</th><th>{tr(lang, "근거", "Evidence")}</th></tr></thead>
            <tbody>
              {x.shape.text != null && <tr><td>U</td><td>user</td><td>trusted</td><td>{tr(lang, "지시 권한", "instruction")}</td><td>{x.shape.text}</td>
                <td>{f.evidence.filter((e: any) => e.location === "text").map((e: any, i: number) => <div key={i} style={{ color: "var(--verdict-block)" }}>{LX(lang, e.note)} @{e.offset}+{e.length}</div>)}</td></tr>}
              {x.segments.map((g: any) => (
                <tr key={g.i} style={{ background: g.hits.length ? "#fdecec" : undefined }}><td>S{g.i}</td><td>{g.source}</td><td>{g.trust}</td><td>{g.trust === "untrusted" ? tr(lang, "데이터 전용 «»", "data only «»") : tr(lang, "지시 권한", "instruction")}</td><td>{g.chars}</td>
                  <td>{g.hits.map((e: any, i: number) => <div key={i} style={{ color: "var(--verdict-block)" }}>{LX(lang, e.note)} @{e.offset}+{e.length}</div>)}</td></tr>
              ))}
              {x.shape.system != null && <tr><td>SYS</td><td>system</td><td>trusted</td><td>{tr(lang, "시스템 지시", "system")}</td><td>{x.shape.system}</td><td /></tr>}
            </tbody></table>
          <p className="p-3 text-xs text-muted">{tr(lang, "«» = 스포트라이팅 경계 — 신뢰할 수 없는 출처는 데이터로만 다룬다.", "«» = spotlighting boundary — untrusted sources are treated as data only.")}</p>
        </section>
        <section className="card space-y-2 p-4 text-sm">
          <h2 className="font-semibold">{tr(lang, "근거 · 같은 trace 판정", "Evidence · same-trace verdicts")}</h2>
          <table className="grid-table text-xs" data-testid="inspect-evidence"><thead><tr><th>kind</th><th>{tr(lang, "위치", "Location")}</th><th>offset·len</th><th>{tr(lang, "근거", "Note")}</th></tr></thead>
            <tbody>{f.evidence.map((e: any, i: number) => <tr key={i}><td>{e.kind}</td><td>{e.location ?? "—"}</td><td>{e.offset != null ? `${e.offset} · ${e.length}` : "—"}</td><td>{LX(lang, e.note)}</td></tr>)}</tbody></table>
          <ul className="text-xs">{x.siblings.map((s: any) => <li key={s.id}><VerdictBadge v={s.effective ?? s.verdict} /> {s.agent} <Link className="text-primary mono" href={`/domains/d1/inspect/${s.id}`}>{s.ruleId}</Link></li>)}</ul>
          <h3 className="pt-2 font-semibold">{tr(lang, "조치", "Actions")}</h3>
          <div className="flex flex-wrap gap-2 text-xs">
            <Link className="btn btn-secondary text-xs" href={`/findings/${f.id}`}>{tr(lang, "이의 신청 · 오탐 표시 → 재판정", "Appeal · mark false positive → re-judge")}</Link>
            <Link className="btn btn-secondary text-xs" href={`/incidents?trace=${f.traceId}`}>{tr(lang, "사건", "Incident")}</Link>
            <Link className="btn btn-secondary text-xs" href="/observability/slo">{tr(lang, "골든셋 · 오탐 예산", "Golden set · FP budget")}</Link>
          </div>
          <p className="text-xs text-muted">{tr(lang, "결정(이의·라벨)은 원장에 추가 기록된다.", "Decisions (appeals · labels) are appended to the ledger.")}</p>
        </section>
      </div>
      <section className="card mt-4 space-y-2 p-4 text-sm">
        <h2 className="font-semibold">{tr(lang, "원문 재검사 — 붙여 넣은 입력으로 세그먼트·은닉 문자·정규화 차분·위치별 지시 (저장 안 함)", "Re-inspect with pasted input — segments · hidden characters · normalization diff · positional directives (no save)")}</h2>
        <Inspector agents={["d1-05", "d1-01", "d1-04"].map((id) => ({ id, label: id }))} samples={{ "d1-05": skeleton, "d1-01": skeleton, "d1-04": skeleton }} />
      </section>
    </>
  );
}
