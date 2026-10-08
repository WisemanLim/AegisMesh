// SCR-H02 근거성·인용 검증 뷰어 — 출력 관문 판정 1건: 문장 근거 구간(위치·지지율), 검색 근거 문서(모양), 인용 검증(형제 판정).
// 원문·최종 출력은 저장돼 있지 않다(MSG-012) — 재검사는 붙여 넣은 출력으로.
import Link from "next/link";
import { notFound } from "next/navigation";
import { Banner, Chip, SeverityBadge, VerdictBadge } from "@/components/Badges";
import { Inspector } from "@/components/Inspector";
import { PageHeader } from "@/components/Shell";
import { ApiError, api } from "@/lib/api";
import { fmtTime, shortHash } from "@/lib/format";
import { tr, LX } from "@/lib/i18n";
import { prefs } from "@/lib/session";

export default async function Grounding({ params }: { params: Promise<{ d: string; fid: string }> }) {
  const [{ lang }, { fid }] = await Promise.all([prefs(), params]);
  let x: any;
  try {
    x = await api(`/v1/domains/d4/grounding/${encodeURIComponent(fid)}`);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound();
    throw e;
  }
  const f = x.finding;
  const cite = x.citation;
  const sample = { output: "", retrieval: x.retrieval.map((d: any) => ({ id: d.id, url: d.url ?? undefined, text: "" })) };
  return (
    <>
      <PageHeader crumb={`${tr(lang, "위험 영역", "Risk domains")} › D4 › ${tr(lang, "근거성 판정", "Groundedness verdict")} › ${f.id}`} title={tr(lang, "근거성·인용 검증 뷰어", "Groundedness & citation viewer")} />
      <div className="mb-3 flex flex-wrap items-center gap-2 text-sm" data-testid="grounding-head">
        <VerdictBadge v={f.effective ?? f.verdict} /><SeverityBadge s={f.severity} /><Chip tone="primary">{f.agent}</Chip><span className="mono">{f.ruleId}</span><span>conf {f.confidence}</span>
        <span className="mono">trace <Link className="text-primary" href={`/findings?trace=${f.traceId}`}>{shortHash(f.traceId)}</Link></span><span className="text-muted">{x.target ?? ""} · {fmtTime(f.at)}</span>
        {!f.valid && <b style={{ color: "var(--verdict-block)" }}>{tr(lang, "무효(근거 없음)", "invalid (no evidence)")}</b>}
      </div>
      <div className="mb-3"><Banner tone="info">{tr(lang, "원문·최종 출력 미보존 — 문장 근거 구간(위치·길이·지지율)과 검색 근거 문서의 식별자만 표시(MSG-012). 사용자에게는 규칙 상세 대신 참조 ID 만(MSG-024).",
        "Raw text and final output not retained — only sentence spans (location · length · support) and retrieved-document identifiers (MSG-012). Users see a reference ID, not rule details (MSG-024).")}</Banner></div>
      <div className="grid grid-cols-2 gap-4">
        <section className="card overflow-hidden text-sm" data-testid="grounding-sentences">
          <h2 className="p-3 font-semibold">{tr(lang, "① 문장 단위 근거성", "① Sentence-level groundedness")}</h2>
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "구간", "Span")}</th><th>{tr(lang, "판정 근거", "Evidence")}</th></tr></thead>
            <tbody>{f.evidence.length === 0 ? <tr><td colSpan={2} className="text-muted">—</td></tr> : f.evidence.map((e: any, i: number) => (
              <tr key={i} style={{ background: e.kind === "span" ? "#fdecec" : undefined }}><td className="mono">{e.offset != null ? `${e.offset}+${e.length}` : e.kind}</td><td>{LX(lang, e.note)}</td></tr>))}</tbody></table>
          <p className="p-3 text-xs text-muted">{lang === "en" ? <>Ungrounded sentences get the output marker <code data-user lang="ko">[근거 미확인]</code> (unverified grounding; display first) or are blocked by policy override. Threshold and mode live in the policy —</> : "근거 미확보 문장은 [근거 미확인] 표시(표시 우선) 또는 정책 재정의로 차단. 임계·모드는 정책에서 —"} <Link className="text-primary" href="/domains/d4/grounding">{tr(lang, "모드 설정", "mode settings")}</Link></p>
        </section>
        <section className="card overflow-hidden text-sm" data-testid="grounding-docs">
          <h2 className="p-3 font-semibold">{tr(lang, "② 검색 근거(컨텍스트) 대조", "② Retrieved evidence (context)")}</h2>
          <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "문서", "Document")}</th><th>URL</th><th>{tr(lang, "신뢰", "Trust")}</th><th>{tr(lang, "서명", "Signed")}</th></tr></thead>
            <tbody>{x.retrieval.length === 0 ? <tr><td colSpan={4} className="text-muted">{tr(lang, "근거 문서 없음 — 근거성 판정 불가(환각과 다름)", "No retrieved documents — groundedness cannot be judged (not the same as hallucination)")}</td></tr> : x.retrieval.map((d: any) => (
              <tr key={d.id}><td className="mono">{d.id}</td><td className="mono">{d.url ?? "—"}</td><td>{d.trust}</td><td>{d.signed == null ? "—" : d.signed ? "✓" : "✗"}</td></tr>))}</tbody></table>
        </section>
        <section className="card space-y-2 p-4 text-sm" data-testid="grounding-citations">
          <h2 className="font-semibold">{tr(lang, "③ 인용 검증 (AG-D4-02)", "③ Citation check (AG-D4-02)")}</h2>
          {!cite ? <p className="text-xs text-muted">{tr(lang, "같은 trace 에 인용 검사 판정 없음", "No citation verdict on this trace")}</p> : (
            <>
              <p className="text-xs"><VerdictBadge v={cite.effective ?? cite.verdict} /> <Link className="text-primary mono" href={`/findings/${cite.id}`}>{cite.ruleId}</Link></p>
              <ul className="text-xs">{cite.evidence.map((e: any, i: number) => <li key={i}>{e.offset != null && <span className="mono">{e.offset}+{e.length} </span>}{LX(lang, e.note)} {e.kind === "span" && <b style={{ color: "var(--verdict-block)" }}>{tr(lang, "→ 자동 제거", "→ removed")}</b>}</li>)}</ul>
            </>)}
          <p className="text-xs text-muted">{lang === "en" ? <>Identifier existence → quote vs source → unverified citations removed (output marker <code data-user lang="ko">[인용 미검증]</code>)</> : "식별자 실재 확인 → 인용문·원문 대조 → 미검증 인용 자동 제거 ([인용 미검증])"}</p>
        </section>
        <section className="card space-y-2 p-4 text-sm">
          <h2 className="font-semibold">{tr(lang, "④ 사용자에게 나간 출력 — 붙여 넣어 재검사", "④ Output sent to the user — paste to re-check")}</h2>
          <Inspector agents={[{ id: "d4-01", label: "d4-01" }, { id: "d4-02", label: "d4-02" }]} samples={{ "d4-01": sample, "d4-02": sample }} />
          <div className="flex gap-2 text-xs"><Link className="btn btn-secondary text-xs" href={`/findings/${f.id}`}>{tr(lang, "이의 제기 · 골든셋 편입", "Appeal · add to golden set")}</Link></div>
        </section>
      </div>
    </>
  );
}
