"use client";
// 도메인 상세 화면 검사기 — 붙여 넣은 요청을 에이전트로 판정하고 엔진 신호·진단(explain)을 보인다. 정책 설정 적용, 저장 없음.
import { startTransition, useActionState, useState } from "react";
import { inspectAgent } from "@/app/domains/actions";
import { tr, LX } from "@/lib/i18n";
import { useLang } from "@/lib/lang";

const V: Record<string, string> = { allow: "#257a6e", alert: "#9d6105", transform: "#3b6fd8", require_approval: "#8a4fd8", block: "#c03333", deny: "#c03333", pass: "#257a6e" };
const Vd = ({ v }: { v?: string | null }) => <b style={{ color: V[v ?? ""] ?? "inherit" }}>{v ?? "—"}</b>;
const ok = (b: boolean) => <span style={{ color: b ? V.allow : V.block }}>{b ? "✓" : "✗"}</span>;

function Table({ head, rows }: { head: string[]; rows: React.ReactNode[][] }) {
  return (
    <table className="grid-table text-xs"><thead><tr>{head.map((h) => <th key={h}>{h}</th>)}</tr></thead>
      <tbody>{rows.length === 0 ? <tr><td colSpan={head.length} className="text-muted">—</td></tr> : rows.map((r, i) => <tr key={i}>{r.map((c, j) => <td key={j}>{c}</td>)}</tr>)}</tbody></table>
  );
}

/** 소형 분류기 이중 판정(OQ4) — 모델·임계·점수를 올린 특징(입력에서 나온 조각, 저장하지 않음) */
function Clf({ c, scores }: { c: any; scores: { label: string; score: number; top: any[] }[] }) {
  const lang = useLang();
  if (!c) return null;
  const best = [...scores].sort((a, b) => b.score - a.score)[0];
  const col = (p: number) => (p >= c.thresholds.block ? V.block : p >= c.thresholds.alert ? V.alert : undefined);
  return (
    <div className="text-xs" data-testid="classifier-explain">
      <p>{tr(lang, "소형 분류기", "Small classifier")} <span className="mono">{c.model}</span> · {tr(lang, "경보", "alert")} ≥ {c.thresholds.alert} · {tr(lang, "차단", "block")} ≥ {c.thresholds.block} · sha <span className="mono">{c.sha256}</span>
        {" · "}{scores.map((x) => <span key={x.label} className="mr-2"><b style={{ color: col(x.score) }}>{x.label} {x.score}</b></span>)}</p>
      {best && best.top.length > 0 && <p className="text-muted">{tr(lang, "점수를 올린 특징", "Features that raised the score")}: <span data-user>{best.top.map((t: any) => t.feature).join(" · ")}</span></p>}
    </div>
  );
}

export function ExplainView({ x }: { x: any }) {
  const lang = useLang();
  if (!x) return null;
  const note = x.note ? <p className="text-xs text-muted">{LX(lang, x.note)}</p> : null;
  switch (x.kind) {
    case "segments":
      return <div className="space-y-1">{note}<Table head={["#", tr(lang, "출처", "Source"), tr(lang, "신뢰", "Trust"), tr(lang, "권한", "Authority"), tr(lang, "글자", "Chars"), tr(lang, "지시 유형", "Directives")]}
        rows={x.segments.map((g: any) => [`S${g.i}`, g.source, g.trust, LX(lang, g.authority), g.chars, g.hits.length ? <b style={{ color: V.block }}>{g.hits.join(", ")}</b> : "—"])} />
        <Clf c={x.classifier} scores={x.segments.filter((g: any) => g.classifier).map((g: any) => ({ label: `S${g.i}`, score: g.classifier.score, top: g.classifier.top }))} /></div>;
    case "unicode":
      return <div className="space-y-2">{note}{x.rows.map((r: any) => (
        <div key={r.location} className="rounded border border-line p-2 text-xs">
          <b>{r.location}</b> — {tr(lang, `렌더 전/후 ${r.chars} / ${r.visibleChars} → 비가시 ${r.invisible} · NFKC ${r.nfkcChars}`, `before/after render ${r.chars} / ${r.visibleChars} → invisible ${r.invisible} · NFKC ${r.nfkcChars}`)}
          {r.runs.map((u: any, i: number) => <div key={i} className="mono" style={{ color: V.block }}>⟦{u.codepoints} · {u.length}{tr(lang, "자", " chars")} · {u.kind} @ {u.offset}⟧</div>)}
          {r.tagDecoded && <div>{tr(lang, "태그 블록 해독: ", "Tag block decoded: ")}<span className="mono" style={{ color: V.block }}>{r.tagDecoded}</span></div>}
        </div>))}</div>;
    case "position":
      return <div className="space-y-1">{note}<p className="text-xs">{tr(lang, `전체 ${x.totalChars}자 · 긴 컨텍스트(≥${x.longContextChars}) ${x.longContext ? "예" : "아니오"} · 후반 기준 ${x.lateFraction}`, `total ${x.totalChars} chars · long context (≥${x.longContextChars}) ${x.longContext ? "yes" : "no"} · late from ${x.lateFraction}`)}</p>
        <Table head={[tr(lang, "위치", "Location"), tr(lang, "상대 위치", "Position"), tr(lang, "후반", "Late")]} rows={x.hits.map((h: any) => [h.location, `${Math.round(h.position * 100)}%`, ok(!h.late)])} /></div>;
    case "goal":
      return <div className="space-y-1">{note}
        <p className="text-xs">{tr(lang, "목표 서명(sha256): ", "Goal signature (sha256): ")}<span className="mono">{x.goalHash ? `${x.goalHash.slice(0, 16)}…` : "—"}</span> · {tr(lang, "목표 행동군", "goal action groups")}: {x.goalGroups.join(", ") || "—"}</p>
        <ol className="space-y-1 text-xs" data-testid="goal-timeline">{x.steps.map((s: any) => (
          <li key={s.i} className="flex items-center gap-2 rounded border border-line px-2 py-1">
            <span className="w-6 text-muted">{s.i + 1}</span><span className="flex-1">{s.step}</span>
            {s.drift.length > 0 && <span style={{ color: V.require_approval }}>{tr(lang, "이탈", "drift")}: {s.drift.join(", ")}</span>}
            {s.override && <span style={{ color: V.block }}>{tr(lang, "목표 재정의", "goal override")}</span>}<Vd v={s.verdict} />
          </li>))}</ol>
        {x.inputOverride.length > 0 && <p className="text-xs" style={{ color: V.block }}>{tr(lang, "입력의 목표 재정의 지시", "Goal-override directive in input")}: {x.inputOverride.join(", ")}</p>}</div>;
    case "jailbreak":
      return <div className="space-y-1">{note}<Table head={[tr(lang, "코퍼스 유형", "Corpus family"), tr(lang, "유사도", "Similarity"), tr(lang, "위치", "Location"), "leet"]}
        rows={x.matches.map((m: any) => [m.family, m.score, m.location, m.leet ? "✓" : ""])} />
        <p className="text-xs">{tr(lang, `최고 ${x.top} · 코퍼스 ${x.corpus}종`, `top ${x.top} · ${x.corpus} corpus families`)}</p>
        <Clf c={x.classifier} scores={(x.classifier?.inputs ?? []).map((i: any) => ({ label: i.location, score: i.score, top: i.top }))} /></div>;
    case "egress":
      return <div className="space-y-1"><p className="text-xs">{tr(lang, `엔트로피 임계 ${x.entropyBits} bits/char · 자동 렌더 차단 ${x.blockAutoRender ? "켬" : "끔"} · 허용 ${x.allowlist.join(", ") || "없음"}`, `entropy ${x.entropyBits} bits/char · block auto-render ${x.blockAutoRender ? "on" : "off"} · allow ${x.allowlist.join(", ") || "none"}`)}</p>
        <Table head={[tr(lang, "종류", "Kind"), tr(lang, "호스트", "Host"), tr(lang, "허용", "Allowed"), tr(lang, "최대 엔트로피", "Max entropy"), tr(lang, "인코딩 파라미터", "Encoded params"), tr(lang, "조치", "Action")]}
          rows={x.urls.map((u: any) => [u.kind, u.host, ok(u.allowed), u.maxEntropy, u.encodedParams, <Vd key="a" v={u.action === "pass" ? "allow" : u.action} />])} /></div>;
    case "leak":
      return <div className="space-y-1 text-xs"><p>{tr(lang, `카나리 ${x.canaries.length}개 · 출력 대조 ${x.matchOutput ? "켬" : "끔"} · ${x.ngram}-gram 재현율 ${x.ratio} (임계 ${x.threshold}) · 숨은 컨텍스트 비밀 형태 ${x.secretInSystem ? "있음" : "없음"}`,
        `${x.canaries.length} canaries · output matching ${x.matchOutput ? "on" : "off"} · ${x.ngram}-gram reproduction ${x.ratio} (threshold ${x.threshold}) · secret-like string in hidden context ${x.secretInSystem ? "yes" : "no"}`)}</p>
        <Table head={[tr(lang, "카나리", "Canary"), tr(lang, "출력에", "In output")]} rows={x.canaries.map((c: any) => [<span key="t" className="mono">{c.token}</span>, c.inOutput ? <b style={{ color: V.block }}>✓</b> : "—"])} /></div>;
    case "pii":
      return <div className="space-y-1 text-xs"><p>{tr(lang, `구역 ${x.zone ?? "(없음)"} · ${x.dictionary}`, `zone ${x.zone ?? "(none)"} · ${x.dictionary}`)}</p>
        <Table head={[tr(lang, "유형", "Type"), tr(lang, "위치", "Location"), "span", tr(lang, "점수", "Score"), tr(lang, "노출 모드", "Mode")]} rows={x.entities.map((e: any) => [e.type, e.location, `${e.offset}–${e.offset + e.length}`, e.score, e.mode])} /></div>;
    case "scope":
      return <Table head={[tr(lang, "항목", "Item"), tr(lang, "테넌트", "Tenant"), tr(lang, "소유자", "Owner"), tr(lang, "세션", "Session")]}
        rows={x.items.map((i: any) => [`${i.kind}:${i.id}`, <>{ok(i.tenantOk)} {i.tenant ?? "—"}</>, <>{ok(i.ownerOk)} {i.owner ?? "—"}</>, <>{ok(i.sessionOk)} {i.session ?? "—"}</>])} />;
    case "access":
      return <div className="space-y-1"><p className="text-xs text-muted">{x.prefilter}</p><Table head={[tr(lang, "문서", "Doc"), "ACL", tr(lang, "주체", "Principal"), tr(lang, "대리", "Agent"), tr(lang, "결정", "Decision")]}
        rows={x.decisions.map((d: any) => [d.doc, (d.acl ?? ["*"]).join(", "), <>{ok(d.principalOk)} {d.principal}</>, d.agent ? <>{ok(d.agentOk)} {d.agent}</> : "—", <Vd key="d" v={d.decision} />])} /></div>;
    case "recall":
      return <p className="text-xs">{tr(lang, `카나리 ${x.canaries}개 중 재현 ${x.canaryHits} · 보호 코퍼스 ${x.corpus.length}건 (${x.ngram}-gram 일치 ${x.corpus.map((c: any) => c.hits).join("/") || 0})`, `${x.canaryHits} of ${x.canaries} canaries reproduced · ${x.corpus.length} protected passages (${x.ngram}-gram hits ${x.corpus.map((c: any) => c.hits).join("/") || 0})`)}</p>;
    case "toolcall":
      return <div className="space-y-1 text-xs">{note}<p>{tr(lang, `도구 ${x.tool ?? "—"} · 고위험 ${x.highRisk ? "예" : "아니오"} · ${x.approved ? "사전 승인" : "미승인"}`, `tool ${x.tool ?? "—"} · high-risk ${x.highRisk ? "yes" : "no"} · ${x.approved ? "pre-approved" : "not approved"}`)}</p>
        {x.dryRun && <div><p>{tr(lang, `드라이런 ${x.dryRun.rows ?? 0}행 / 임계 ${x.rowLimit} → ${x.ratio}배 · 되돌림 ${x.dryRun.reversible === false ? "불가" : "가능"} · 테이블 ${(x.dryRun.tables ?? []).join(", ") || "—"}`, `dry run ${x.dryRun.rows ?? 0} rows / limit ${x.rowLimit} → ${x.ratio}× · reversible ${x.dryRun.reversible === false ? "no" : "yes"} · tables ${(x.dryRun.tables ?? []).join(", ") || "—"}`)}</p>
          <div className="h-2 rounded bg-[#eef0f4]"><div className="h-2 rounded" style={{ width: `${Math.min(100, (x.ratio ?? 0) * 100 / Math.max(1, Math.ceil(x.ratio ?? 1)))}%`, background: (x.ratio ?? 0) > 1 ? V.require_approval : V.allow }} /></div></div>}
        <Table head={[tr(lang, "인자", "Arg"), tr(lang, "글자", "Chars"), tr(lang, "파괴적 SQL", "Destructive SQL"), tr(lang, "WHERE 없는 쓰기", "Unbounded write")]} rows={x.args.map((a: any) => [a.arg, a.chars, ok(!a.destructiveSql), ok(!a.unboundedWrite)])} /></div>;
    case "injection":
      return <div className="space-y-1">{note}<Table head={[tr(lang, "인자", "Arg"), tr(lang, "셸 문맥", "Shell ctx"), tr(lang, "메타문자", "Metachar"), tr(lang, "명령 치환", "Substitution"), "SQL", tr(lang, "SQL 주입", "SQLi")]}
        rows={x.args.map((a: any) => [a.arg, a.shellContext ? "✓" : "", ok(!a.shellMeta), ok(!a.substitution), a.sqlContext ? "✓" : "", ok(!a.sqlInjection)])} /></div>;
    case "ioc":
      return <div className="space-y-1">{note}<Table head={[tr(lang, "인자", "Arg"), tr(lang, "지표", "Indicator"), tr(lang, "점수", "Score")]} rows={x.hits.map((h: any) => [h.arg, <b key="i" style={{ color: V.block }}>{h.ioc}</b>, h.score])} /></div>;
    case "paths":
      return <div className="space-y-1 text-xs"><p>{tr(lang, `허용 루트 ${x.roots.join(", ")} · 읽기 전용 ${x.readOnly.join(", ") || "없음"}`, `allowed roots ${x.roots.join(", ")} · read-only ${x.readOnly.join(", ") || "none"}`)}</p>
        <Table head={[tr(lang, "입력", "Input"), tr(lang, "정규화", "Normalized"), tr(lang, "이탈", "Traversal"), tr(lang, "루트 안", "In root"), tr(lang, "읽기 전용", "RO"), tr(lang, "민감", "Sensitive"), tr(lang, "조치", "Action")]}
          rows={x.paths.map((p: any) => [<span key="i" className="mono">{p.input}</span>, <span key="n" className="mono">{p.normalized}</span>, ok(!p.traversal), ok(p.insideRoot), p.readOnly ? "✓" : "", ok(!p.sensitive), <Vd key="a" v={p.action} />])} /></div>;
    case "usage":
      return <div className="space-y-1 text-xs">{note}<p>{tr(lang, `주체 ${x.principal ?? "—"} · 레이트 ${x.rateLimit ? `${x.rateLimit.calls}/${x.rateLimit.windowSec ?? 60}s` : "—"} (최근 ${x.recentCalls ?? "—"}) · 일 쿼터 ${x.quota?.perDay ?? "—"} (오늘 ${x.usageToday ?? "—"}) · 최대 일괄 ${x.maxBatch}`,
        `principal ${x.principal ?? "—"} · rate ${x.rateLimit ? `${x.rateLimit.calls}/${x.rateLimit.windowSec ?? 60}s` : "—"} (recent ${x.recentCalls ?? "—"}) · daily quota ${x.quota?.perDay ?? "—"} (today ${x.usageToday ?? "—"}) · max batch ${x.maxBatch}`)}</p></div>;
    case "scopes":
      return <div className="space-y-1 text-xs"><Table head={[tr(lang, "항목", "Item"), tr(lang, "범위", "Scopes")]} rows={[
        [tr(lang, "주체", "Principal"), x.principalScopes.join(", ") || "—"], [tr(lang, "대리 에이전트", "Delegate agent"), x.agentScopes ? x.agentScopes.join(", ") || "—" : "—"],
        [tr(lang, "유효(교집합)", "Effective (intersection)"), x.effective ? x.effective.join(", ") || "—" : "—"], [tr(lang, "도구 요구", "Tool requires"), x.required.join(", ") || "—"],
        [tr(lang, "다운스코핑 토큰", "Downscoped token"), x.downscoped.join(", ") || "—"], [tr(lang, "부족", "Missing"), x.missing.length ? <b key="m" style={{ color: V.block }}>{x.missing.join(", ")}</b> : "—"]]} />
        {x.history.length > 0 && <p>{tr(lang, "직전 도구", "Prior tools")}: {x.history.join(" → ")} → {x.tool}</p>}</div>;
    case "registry":
      return <p className="text-xs">{tr(lang, `도구 ${x.tool ?? "—"} · 허용목록 ${x.allowlist ? (x.allowlisted ? "포함 ✓" : "밖 ✗") : "미설정"} · 코드 실행 ${x.codeExec ? "예" : "아니오"} · ${x.approved ? "승인됨" : "미승인"}`, `tool ${x.tool ?? "—"} · allowlist ${x.allowlist ? (x.allowlisted ? "in ✓" : "out ✗") : "unset"} · code exec ${x.codeExec ? "yes" : "no"} · ${x.approved ? "approved" : "not approved"}`)}</p>;
    case "grounding":
      return <div className="space-y-1">{note}<Table head={[tr(lang, "문장", "Sentence"), tr(lang, "주장", "Claim"), tr(lang, "지지율", "Support"), tr(lang, "수치", "Numbers"), tr(lang, "근거 문서", "Doc"), tr(lang, "근거", "Grounded")]}
        rows={x.sentences.map((r: any) => [r.sentence, r.claim ? "✓" : "", r.support ?? "—", ok(r.numbersOk), r.doc ?? "—", <span key="g" style={{ color: r.grounded ? V.allow : V.block }}>{r.grounded ? "✓" : tr(lang, "근거 미확인", "ungrounded")}</span>])} /></div>;
    case "citations":
      return <div className="space-y-1">{note}<Table head={[tr(lang, "종류", "Kind"), tr(lang, "인용", "Citation"), tr(lang, "실재", "Known"), tr(lang, "규칙", "Rule"), tr(lang, "조치", "Action")]}
        rows={x.citations.map((c: any) => [c.kind, <span key="r" className="mono">{c.ref}</span>, ok(c.known), c.rule ?? "—", c.action === "remove" ? <b key="a" style={{ color: V.block }}>{tr(lang, "제거", "remove")}</b> : tr(lang, "유지", "keep")])} /></div>;
    case "decision":
      return <div className="space-y-1 text-xs"><p>{tr(lang, `행동 ${x.action ?? "—"} (${x.impact ?? "—"}, 되돌림 ${x.reversible === false ? "불가" : "가능"}) · 신뢰도 ${x.confidence ?? "—"} · 적용 임계 ${x.threshold}${x.matched ? ` (${x.matched})` : " (기본)"} · 차단 하한 ${x.blockBelow}`,
        `action ${x.action ?? "—"} (${x.impact ?? "—"}, reversible ${x.reversible === false ? "no" : "yes"}) · confidence ${x.confidence ?? "—"} · threshold ${x.threshold}${x.matched ? ` (${x.matched})` : " (default)"} · block below ${x.blockBelow}`)} → <Vd v={x.result === "pass" ? "allow" : x.result === "approved" ? "allow" : x.result} /></p>
        <Table head={[tr(lang, "행동", "Action"), tr(lang, "임계", "Threshold")]} rows={[...Object.entries(x.thresholds ?? {}).map(([k, v]) => [k, String(v)]), [tr(lang, "기본", "default"), String(x.default)]]} /></div>;
    case "logic":
      return <div className="space-y-1">{note}<Table head={[tr(lang, "식", "Expression"), tr(lang, "출력 값", "Stated"), tr(lang, "재계산", "Recomputed"), ""]} rows={x.equations.map((e: any) => [<span key="e" className="mono">{e.expr}</span>, e.stated, e.recomputed, ok(e.ok)])} />
        {x.samples.length > 0 && <p className="text-xs">{tr(lang, `자기일관성 — 표본 ${x.samples.length}개 일치율 ${Math.round((x.agreement ?? 0) * 100)}%`, `Self-consistency — ${x.samples.length} samples, agreement ${Math.round((x.agreement ?? 0) * 100)}%`)} {x.samples.map((s: any) => <span key={s.sample} className="mono">[{s.numbers.join(" ")}]{s.agree ? "✓" : "✗"} </span>)}</p>}</div>;
    case "compliance":
      return <div className="space-y-1"><Table head={[tr(lang, "문구", "Phrase"), tr(lang, "규칙", "Rule"), tr(lang, "조치", "Action")]} rows={x.matches.map((m: any) => [m.phrase, m.rule, <Vd key="v" v={m.verdict} />])} />
        <p className="text-xs">{tr(lang, `사전 내장 ${x.dictionary.builtin} · 조직 ${x.dictionary.org} · 광고 미고지 ${x.adUndisclosed ? "예" : "아니오"}`, `dictionary built-in ${x.dictionary.builtin} · org ${x.dictionary.org} · undisclosed ad ${x.adUndisclosed ? "yes" : "no"}`)}</p></div>;
    case "propagation":
      return <p className="text-xs">{tr(lang, `전파 대상 ${x.destination} · 출처 표기 ${x.cited ? "있음" : "없음"} · 검증 실패 표시 ${x.unverifiedMarks} · 게이트 ${x.gated ? "적용" : "사용자 응답(대상 아님)"}`, `destination ${x.destination} · provenance ${x.cited ? "yes" : "no"} · unverified marks ${x.unverifiedMarks} · gate ${x.gated ? "applies" : "user reply (n/a)"}`)}</p>;
    case "authn":
      return <p className="text-xs">{tr(lang, `인증 ${x.method ?? "—"} · MFA ${x.mfa ? "예" : "아니오"} · 서명 신원 ${x.signed ? "예" : "아니오"} · SVID 증명 ${x.attested ? "예" : "아니오"} · 주체 유형 ${x.principalType ?? "—"}${x.alg ? ` · alg ${x.alg}` : ""}`, `auth ${x.method ?? "—"} · MFA ${x.mfa ? "yes" : "no"} · signed identity ${x.signed ? "yes" : "no"} · SVID attested ${x.attested ? "yes" : "no"} · principal type ${x.principalType ?? "—"}${x.alg ? ` · alg ${x.alg}` : ""}`)} — {tr(lang, x.advice, "workloads should use SPIFFE SVID (mTLS) or OIDC; retire static API keys and shared secrets after migrating")}</p>;
    case "authz":
      return <Table head={[tr(lang, "검사", "Check"), tr(lang, "값", "Value"), ""]} rows={[[tr(lang, "테넌트", "Tenant"), `${x.tenant} / ${x.resource?.tenant ?? "—"}`, ok(x.tenantOk)],
        [tr(lang, "소유자", "Owner"), `${x.principal ?? "—"} / ${x.resource?.owner ?? "—"}`, ok(x.ownerOk)], [tr(lang, "필수 역할", "Required roles"), `${x.requiredRoles.join(", ") || "—"} ∩ ${x.roles.join(", ") || "—"}`, ok(x.rolesOk)]]} />;
    case "session":
      return <p className="text-xs">{x.session == null ? tr(lang, "세션 정보 없음", "No session") : tr(lang, `세션 ${x.session} · 바인딩 ${x.bound ? "있음" : "없음"} · 장치 지문 변경 ${x.fingerprintChanged ? "예" : "아니오"} · IP 변경 ${x.ipChanged ? "예" : "아니오"}`, `session ${x.session} · bound ${x.bound ? "yes" : "no"} · fingerprint changed ${x.fingerprintChanged ? "yes" : "no"} · IP changed ${x.ipChanged ? "yes" : "no"}`)}</p>;
    case "identity":
      return <div className="space-y-1"><Table head={[tr(lang, "주체", "Subject"), tr(lang, "유형", "Type"), tr(lang, "주장 SPIFFE", "Claimed SPIFFE"), tr(lang, "증명 SVID", "Attested SVID"), ""]}
        rows={x.subjects.map((r: any) => [`${r.who}:${r.id}`, r.type, r.claimed ?? "—", r.attested ?? "—", r.match == null ? "—" : ok(r.match)])} />
        <p className="text-xs">{tr(lang, `서명 신원 ${x.signedIdentity ? "예" : "아니오"} · 권한자 사칭 ${x.claimedAuthority.length ? x.claimedAuthority.join(", ") : "없음"}`, `signed identity ${x.signedIdentity ? "yes" : "no"} · authority claims ${x.claimedAuthority.length ? x.claimedAuthority.join(", ") : "none"}`)}</p></div>;
    case "delegation":
      return <div className="space-y-1 text-xs"><Table head={[tr(lang, "항목", "Item"), tr(lang, "값", "Value")]} rows={[[tr(lang, "주체", "Principal"), `${x.human ?? "—"} · ${x.humanScopes.join(", ") || "—"}`],
        [tr(lang, "대리자", "Delegate"), `${x.agent ?? "—"} · ${x.agentScopes ? x.agentScopes.join(", ") || "—" : "—"}`], [tr(lang, "유효(교집합)", "Effective"), x.effective.join(", ") || "—"],
        [tr(lang, "위임 증명", "Delegation proof"), ok(x.delegationProof)], [tr(lang, "에이전트 초과 역할", "Agent extra roles"), x.agentExtraRoles.join(", ") || "—"]]} /></div>;
    case "token":
      return <p className="text-xs">{!x.present ? tr(lang, "토큰 클레임 없음", "No token claims") : tr(lang, `aud ${x.aud.join(", ") || "없음"} (기대 ${x.expected ?? "—"}) · azp ${x.azp ?? "—"} · 수명 ${x.lifetimeSec ?? "—"}초 / 상한 ${x.maxLifetimeSec} · 남은 ${x.expiresIn ?? "—"}초 · 바인딩 ${x.binding}`,
        `aud ${x.aud.join(", ") || "none"} (expected ${x.expected ?? "—"}) · azp ${x.azp ?? "—"} · lifetime ${x.lifetimeSec ?? "—"}s / max ${x.maxLifetimeSec} · expires in ${x.expiresIn ?? "—"}s · binding ${x.binding}`)}</p>;
    case "inventory":
      return <Table head={[tr(lang, "주체", "Principal"), tr(lang, "유형", "Type"), tr(lang, "부여", "Granted"), tr(lang, "사용", "Used"), tr(lang, "미사용", "Unused"), "*"]}
        rows={x.principals.map((p: any) => [p.id, p.type ?? "—", p.granted, p.used, p.unused.join(", ") || "—", p.wildcard ? "⚠" : ""])} />;
    case "autonomy":
      return <div className="space-y-1 text-xs">{note}<p>{tr(lang, `행동 ${x.action ?? "—"} (impact ${x.impact ?? "—"}${x.external ? " · 외부" : ""}${x.reversible === false ? " · 비가역" : ""}) → 등급 I${x.need ?? "—"} · 자율 레벨 ${x.level}`, `action ${x.action ?? "—"} (impact ${x.impact ?? "—"}${x.external ? " · external" : ""}${x.reversible === false ? " · irreversible" : ""}) → grade I${x.need ?? "—"} · autonomy level ${x.level}`)} → <Vd v={x.result === "auto" || x.result === "approved" ? "allow" : x.result} /></p>
        <div className="flex gap-1">{x.table.map((g: any) => <span key={g.grade} className="rounded px-2 py-0.5" style={{ background: g.auto ? "#e8f6f4" : "#f4ecfd", color: g.auto ? V.allow : V.require_approval }}>{g.grade} {g.auto ? tr(lang, "자동", "auto") : tr(lang, "승인", "approve")}</span>)}</div></div>;
    case "lineage":
      return <div className="space-y-1 text-xs"><p>{tr(lang, `깊이 ${x.depth} / 상한 ${x.maxDepth} · 생성 ${x.spawned} / 팬아웃 상한 ${x.maxFanout} · 생성 예산 ${x.spawnBudget ?? "—"}`, `depth ${x.depth} / max ${x.maxDepth} · spawned ${x.spawned} / fan-out max ${x.maxFanout} · spawn budget ${x.spawnBudget ?? "—"}`)}</p>
        <Table head={[tr(lang, "에이전트", "Agent"), tr(lang, "부모", "Parent"), tr(lang, "깊이", "Depth"), tr(lang, "도구", "Tool")]} rows={x.nodes.map((n: any) => [n.agent ?? "—", n.parent ?? "—", n.depth, n.tool ?? "—"])} /></div>;
    case "loop":
      return <div className="space-y-1 text-xs"><p>{tr(lang, `반복 임계 ${x.maxRepeat} · 진전 없음 임계 ${x.maxNoProgress} · 실행 ${x.elapsedSec ?? "—"}초 / ${x.maxRunSec}초 · 호출 ${x.calls}`, `repeat limit ${x.maxRepeat} · no-progress limit ${x.maxNoProgress} · run ${x.elapsedSec ?? "—"}s / ${x.maxRunSec}s · calls ${x.calls}`)}</p>
        <div className="flex flex-wrap gap-1">{x.states.map((st: any, i: number) => <span key={i} className="mono rounded px-1" style={{ background: st.repeat ? "#fdecec" : "#f6f7f9", color: st.repeat ? V.block : undefined }}>{st.hash}</span>)}</div></div>;
    case "contract":
      return <Table head={[tr(lang, "계약 항목", "Contract"), tr(lang, "값", "Value")]} rows={[[tr(lang, "출처", "Source"), x.source ?? tr(lang, "없음", "none")], [tr(lang, "목표", "Goal"), x.goal ?? "—"],
        [tr(lang, "허용 도구", "Allowed tools"), (x.tools ?? []).join(", ") || "—"], [tr(lang, "행동", "Actions"), (x.actions ?? []).join(", ") || "—"], [tr(lang, "하위 과업 상한", "Max subtasks"), `${x.planSteps} / ${x.maxSubtasks ?? "—"}`],
        [tr(lang, "이 호출", "This call"), `${x.tool ?? ""} ${x.action ?? ""}`]]} />;
    case "means":
      return <p className="text-xs">{tr(lang, `금지 수단 내장 ${x.builtin.length} · 조직 ${x.org.length} — 일치 ${x.matches.map((m: any) => `${m.rule}@${m.location}`).join(", ") || "없음"}`, `forbidden means built-in ${x.builtin.length} · org ${x.org.length} — matches ${x.matches.map((m: any) => `${m.rule}@${m.location}`).join(", ") || "none"}`)}</p>;
    case "quota":
      return <div className="space-y-1">{note}<Table head={[tr(lang, "차원", "Dimension"), tr(lang, "사용", "Used"), tr(lang, "쿼터", "Quota"), tr(lang, "비율", "Ratio")]} rows={x.dims.map((d: any) => [d.dim, d.used ?? "—", d.quota ?? "—", d.ratio == null ? "—" : `${Math.round(d.ratio * 100)}%`])} /></div>;
    case "spend":
      return <Table head={[tr(lang, "항목", "Item"), tr(lang, "값", "Value")]} rows={[[tr(lang, "행동·금액", "Action · amount"), `${x.action} · ${x.amount?.toLocaleString?.("en-US") ?? "—"}`],
        [tr(lang, "건당 상한 / 승인 임계", "Per-tx limit / approval"), `${x.spendLimit.toLocaleString("en-US")} / ${x.approvalThreshold.toLocaleString("en-US")}`], [tr(lang, "오늘 / 일 상한", "Today / daily"), `${x.dailySpent ?? "—"} / ${x.dailyLimit ?? "—"}`],
        [tr(lang, "보상 트랜잭션", "Compensation"), x.compensation ?? (x.requireCompensation ? tr(lang, "없음 → 거부", "none → refused") : "—")], [tr(lang, "되돌림", "Reversible"), x.reversible == null ? "—" : ok(x.reversible)]]} />;
    default:
      return <pre tabIndex={0} className="mono max-h-48 overflow-auto rounded bg-[#f6f7f9] p-2 text-[11px]">{JSON.stringify(x, null, 1)}</pre>;
  }
}

export function InspectResult({ r }: { r: any }) {
  const lang = useLang();
  const f = r.finding;
  return (
    <div className="space-y-2 text-xs" data-testid="inspect-result">
      <p><b>{r.agent}</b> · <Vd v={f.verdict} /> · {f.ruleId} · conf {f.confidence} · {f.severity}{!f.valid && <b style={{ color: V.block }}>{tr(lang, " · 무효(근거 없음)", " · invalid (no evidence)")}</b>} · {tr(lang, "엔진", "engine")} {r.engine}</p>
      {r.others.length > 0 ? <p>{tr(lang, "이중 판정", "Dual judgment")}: {r.others.map((o: any) => `${o.engine} → ${o.verdict} ${o.confidence}`).join(" · ")} — {r.others.every((o: any) => o.verdict === f.verdict) ? tr(lang, "일치", "agree") : <b style={{ color: V.alert }}>{tr(lang, "불일치 → 사람 검토", "disagree → human review")}</b>}</p>
        : <p className="text-muted">{tr(lang, `엔진 ${r.engines.length}개(${r.engines.map((e: any) => `${e.id}:${e.kind}`).join(", ")}) — 내장 엔진 1개라 이중 판정 없음`, `${r.engines.length} engine(s) (${r.engines.map((e: any) => `${e.id}:${e.kind}`).join(", ")}) — single built-in engine, no dual judgment`)}</p>}
      {f.action?.transform && <div><b>{tr(lang, "무해화 결과", "Sanitized output")}</b><pre className="mono whitespace-pre-wrap rounded bg-[#f6f7f9] p-2">{f.action.transform}</pre></div>}
      <ExplainView x={r.explain} />
      {r.signals.length > 0 && <details><summary className="cursor-pointer text-muted">{tr(lang, `엔진 신호 ${r.signals.length}`, `${r.signals.length} engine signals`)}</summary>
        <Table head={["rule", tr(lang, "점수", "Score"), tr(lang, "위치", "Location"), "span", tr(lang, "근거", "Note")]}
          rows={r.signals.map((s: any) => [s.rule, s.score, s.evidence.location ?? "—", s.evidence.offset != null ? `${s.evidence.offset}+${s.evidence.length}` : "—", s.evidence.note])} /></details>}
      <p className="text-muted">{tr(lang, "저장·원장 기록 없음 — 붙여 넣은 원문은 이 응답에만 쓰인다(NFR-D1)", "Not stored or recorded — the pasted text is used only for this response (NFR-D1)")}</p>
    </div>
  );
}

export function Inspector({ agents, samples }: { agents: { id: string; label: string }[]; samples: Record<string, object> }) {
  const lang = useLang();
  const [agent, setAgent] = useState(agents[0]?.id ?? "");
  const [req, setReq] = useState(JSON.stringify(samples[agents[0]?.id] ?? {}, null, 1));
  const [s, action, pending] = useActionState(inspectAgent, null);
  const run = () => {
    const fd = new FormData();
    fd.set("agent", agent);
    fd.set("request", req);
    startTransition(() => action(fd));
  };
  return (
    <div className="space-y-2 text-sm" data-testid="inspector">
      <div className="flex gap-2">
        {agents.length > 1 && (
          <select className="input text-xs" value={agent} aria-label="agent" onChange={(e) => { setAgent(e.target.value); setReq(JSON.stringify(samples[e.target.value] ?? {}, null, 1)); }}>
            {agents.map((a) => <option key={a.id} value={a.id}>{a.label}</option>)}
          </select>
        )}
        <button type="button" className="btn btn-primary text-xs" onClick={run} disabled={pending} data-testid="inspect-run">{tr(lang, "검사 (저장 안 함)", "Inspect (no save)")}</button>
      </div>
      <textarea className="input mono h-32 w-full text-xs" value={req} onChange={(e) => setReq(e.target.value)} spellCheck={false} aria-label="request json" data-user />
      {s && !s.ok && <p role="alert" className="text-xs text-red-600">{s.error}</p>}
      {s?.ok && <InspectResult r={s.data} />}
    </div>
  );
}
