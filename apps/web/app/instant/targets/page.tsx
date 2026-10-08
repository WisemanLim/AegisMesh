// SCR-C05 즉시 사용 ② 보호 대상 등록 — 엔드포인트·관문 삽입·모델 공급자(외부는 정책 명시 허용)·MCP 서버(서명)·이그레스 허용목록·인증서 고정, 연결 시험.
import Link from "next/link";
import { Banner, Chip } from "@/components/Badges";
import { InstantSteps, wizardHref } from "@/components/InstantSteps";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { t as tk, tr, LX } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { deleteTarget, saveTarget, testConnection } from "../wizard-actions";

const KINDS: [string, string, string][] = [["chatbot", "상담 챗봇", "Chatbot"], ["coding_agent", "코딩 에이전트", "Coding agent"], ["workflow", "업무 에이전트", "Workflow agent"], ["rag", "검색 증강(RAG)", "RAG"], ["other", "기타", "Other"]];
const INS: [string, string, string][] = [["gateway", "중앙 게이트웨이", "Central gateway"], ["sidecar", "사이드카", "Sidecar"], ["sdk", "SDK", "SDK"]];
const CONN: Record<string, [string, string, string]> = { connected: ["연결 ✓", "Connected ✓", "var(--verdict-allow)"], bound: ["적용됨 · 수신 대기", "Bound · waiting", "#9d6105"], unbound: ["미적용", "Not bound", "var(--sev-info)"] };

export default async function InstantTargets({ searchParams }: { searchParams: Promise<{ p?: string; t?: string; msg?: string; edit?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const { p, t, msg, edit } = await searchParams;
  const write = can(user, "policy.write");
  const [{ data }, prof] = await Promise.all([safe(api("/v1/targets"), { items: [] as any[] }), p ? safe(api("/v1/profiles"), { items: [] as any[] }) : Promise.resolve({ data: { items: [] as any[] } })]);
  const deny = prof.data.items.find((x: any) => x.id === p)?.region?.modelEgress === "deny";
  const cur = data.items.find((x: any) => x.name === (edit ?? t));
  const kindL = (k: string) => { const r = KINDS.find(([v]) => v === k); return r ? tr(lang, r[1], r[2]) : k; };
  const insL = (k: string) => { const r = INS.find(([v]) => v === k); return r ? tr(lang, r[1], r[2]) : k; };
  return (
    <>
      <PageHeader crumb={`${tk(lang, "instant")} › ${tr(lang, "보호 대상", "Targets")}`} title={tr(lang, "즉시 사용 ② 보호 대상 등록", "Instant use ② register protected targets")} />
      <InstantSteps lang={lang} at={2} p={p} t={t} next={wizardHref("preview", p, t)} nextOk={!!p && !!t && data.items.some((x: any) => x.name === t)}
        nextNote={tr(lang, "프로파일 선택 + 보호 대상 1개 선택 필요 (MSG-003)", "Choose a profile and one target (MSG-003)")} />
      {msg && <div className="mb-3"><Banner tone={/^(실패|Failed)/.test(msg) ? "danger" : "info"}>{msg}</Banner></div>}
      <section className="card mb-4 overflow-hidden text-sm" data-testid="targets">
        <h2 className="p-3 font-semibold">{tr(lang, "보호 대상 목록 — 게이트웨이가 요청·도구 호출·응답을 4관문으로 통과시킨다", "Protected targets — the gateway passes requests, tool calls and responses through the four gates")}</h2>
        <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "이름", "Name")}</th><th>{tr(lang, "유형", "Kind")}</th><th>{tr(lang, "엔드포인트", "Endpoint")}</th><th>{tr(lang, "관문 삽입", "Insertion")}</th><th>{tr(lang, "모델 공급자", "Model provider")}</th><th>{tr(lang, "적용 프로파일", "Profile")}</th><th>{tr(lang, "상태", "Status")}</th><th /></tr></thead>
          <tbody>{data.items.length === 0 ? <tr><td colSpan={8} className="text-muted">{tr(lang, "등록된 보호 대상 없음 — 아래에서 추가", "No targets yet — add one below")}</td></tr> : data.items.map((x: any) => {
            const c = CONN[x.connection] ?? CONN.unbound;
            return (
              <tr key={x.id} className={x.name === t ? "bg-primary-soft" : undefined}>
                <td><Link className="mono text-primary" href={wizardHref("targets", p, x.name)}>{x.name}</Link></td><td>{kindL(x.kind)}</td><td className="mono">{x.endpoint}</td><td>{insL(x.insertion)}</td>
                <td>{x.externalModel ? <span title={x.modelProvider}>{tr(lang, "외부", "External")} · <span className="mono">{x.modelProvider}</span></span> : tr(lang, "자체 호스팅", "Self-hosted")}{x.modelEgress === "deny" && <Chip>{tr(lang, "외부 금지", "egress deny")}</Chip>}</td>
                <td>{x.application ? `${x.application.profile} · ${x.application.stage}` : "—"}</td>
                <td><b style={{ color: c[2] }}>{tr(lang, c[0], c[1])}</b>{x.records24h ? <span className="text-muted"> · {x.records24h}/24h</span> : null}</td>
                <td>{write && <div className="flex gap-1">
                  <form action={testConnection}><input type="hidden" name="name" value={x.name} /><input type="hidden" name="bound" value={x.application ? "1" : "0"} /><input type="hidden" name="p" value={p ?? ""} />
                    <button className="btn btn-secondary h-6 text-xs">{tr(lang, "연결 시험", "Test")}</button></form>
                  <Link className="btn btn-secondary h-6 text-xs" href={`${wizardHref("targets", p, x.name)}&edit=${encodeURIComponent(x.name)}`}>{tr(lang, "편집", "Edit")}</Link>
                  <form action={deleteTarget}><input type="hidden" name="id" value={x.id} /><input type="hidden" name="p" value={p ?? ""} />
                    <button className="btn btn-secondary h-6 text-xs" disabled={!!x.application} title={x.application ? tr(lang, "적용된 프로파일이 있다 — 먼저 해제", "Profile applied — release first") : undefined}>{tr(lang, "삭제", "Delete")}</button></form>
                </div>}</td>
              </tr>
            );
          })}</tbody></table>
      </section>
      {cur && (
        <section className="card mb-4 grid grid-cols-2 gap-4 p-4 text-sm" data-testid="target-detail">
          <div>
            <h2 className="mb-2 font-semibold">{tr(lang, "MCP 서버 · 도구", "MCP servers · tools")} — {cur.name}</h2>
            {cur.mcpServers.length === 0 ? <p className="text-xs text-muted">—</p> : <ul className="space-y-1 text-xs">{cur.mcpServers.map((m: any) => (
              <li key={m.name}><span className="mono">{m.name}</span> — {m.refused ? <b style={{ color: "var(--verdict-block)" }}>{tr(lang, "미서명 → 등록 거부", "unsigned → refused")}</b>
                : m.signed ? tr(lang, "서명 ✓", "signed ✓") : m.lastVerdict ? `${tr(lang, "점검", "scan")} ${m.lastVerdict}` : <Link className="text-primary" href="/domains/d7/review">{tr(lang, "점검 기록 없음 — 등록 심사", "no scan — review it")}</Link>}</li>))}</ul>}
            <p className="mt-1 text-xs text-muted">{tr(lang, "도구 허용목록 = 도구 관문 기본값 · 서명 위반 시 즉시 제외", "Tool allowlist = tool-gate default · removed at once on a signature violation")}</p>
          </div>
          <div>
            <h2 className="mb-2 font-semibold">{tr(lang, "이그레스 허용목록 · 인증서 고정 (D7-07)", "Egress allowlist · certificate pinning (D7-07)")}</h2>
            <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "목적지", "Destination")}</th><th>SPKI pin</th></tr></thead>
              <tbody>{cur.egress.length === 0 ? <tr><td colSpan={2} className="text-muted">—</td></tr> : cur.egress.map((e: any) => <tr key={e.host}><td className="mono">{e.host}</td><td className="mono">{e.pin ?? "—"}</td></tr>)}</tbody></table>
            <p className="mt-1 text-xs text-muted">{tr(lang, "허용목록 밖 이그레스 차단 · 핀 불일치 = 연결 차단·alert (AG-D7-07)", "Egress outside the allowlist is blocked · pin mismatch = connection blocked + alert (AG-D7-07)")}</p>
          </div>
        </section>
      )}
      {write && (
        <form action={saveTarget} className="card grid grid-cols-2 gap-3 p-4 text-sm" data-testid="target-form">
          <input type="hidden" name="p" value={p ?? ""} />
          <h2 className="col-span-2 font-semibold">{edit ? tr(lang, `대상 편집 — ${edit}`, `Edit target — ${edit}`) : tr(lang, "대상 추가", "Add target")}</h2>
          <label className="text-xs">{tr(lang, "이름 (영문·숫자·.-_)", "Name (letters, digits, .-_)")}<input name="name" required defaultValue={edit ? cur?.name : ""} readOnly={!!edit} className="input mt-1 w-full" /></label>
          <label className="text-xs">{tr(lang, "유형", "Kind")}<select name="kind" defaultValue={edit ? cur?.kind : "chatbot"} className="input mt-1 w-full">{KINDS.map(([v, ko, en]) => <option key={v} value={v}>{tr(lang, ko, en)}</option>)}</select></label>
          <label className="text-xs">{tr(lang, "엔드포인트 (host[:port][/path] — MSG-004)", "Endpoint (host[:port][/path] — MSG-004)")}<input name="endpoint" required defaultValue={edit ? cur?.endpoint : ""} placeholder="chat.garam.example" className="input mono mt-1 w-full" /></label>
          <fieldset className="text-xs"><legend>{tr(lang, "관문 삽입", "Insertion")}</legend>
            <div className="mt-1 flex gap-3">{INS.map(([v, ko, en]) => <label key={v} className="flex items-center gap-1"><input type="radio" name="insertion" value={v} defaultChecked={(edit ? cur?.insertion : "gateway") === v} />{tr(lang, ko, en)}</label>)}</div></fieldset>
          <fieldset className="text-xs"><legend>{tr(lang, "모델 공급자", "Model provider")}</legend>
            <div className="mt-1 flex flex-wrap items-center gap-3">
              <label className="flex items-center gap-1"><input type="radio" name="provider" value="self" defaultChecked={!(edit && cur?.externalModel)} />{tr(lang, "자체 호스팅 (기본)", "Self-hosted (default)")}</label>
              <label className="flex items-center gap-1"><input type="radio" name="provider" value="external" defaultChecked={!!(edit && cur?.externalModel)} />{tr(lang, "외부 공급자", "External provider")}</label>
              <input name="modelProvider" defaultValue={edit && cur?.externalModel ? cur.modelProvider : ""} placeholder="api.vendor.example" className="input mono h-7 w-48 text-xs" aria-label="external provider" />
            </div>
            {deny && <p className="mt-1" style={{ color: "var(--verdict-block)" }}>{tr(lang, `⚠ ${p}: region.modelEgress = deny — 외부 호출은 금지, 켜려면 승인·증적 (MSG-013)`, `⚠ ${p}: region.modelEgress = deny — external calls denied; enabling needs approval + evidence (MSG-013)`)}</p>}</fieldset>
          <label className="text-xs">{tr(lang, "MCP 서버 (쉼표 구분)", "MCP servers (comma-separated)")}<input name="mcpServers" defaultValue={edit ? cur?.mcpServers.map((m: any) => m.name).join(", ") : ""} placeholder="mcp-core-banking, mcp-jira" className="input mono mt-1 w-full" /></label>
          <label className="text-xs">{tr(lang, "이그레스 허용목록 — 한 줄에 `host:port [SPKI pin]`", "Egress allowlist — one `host:port [SPKI pin]` per line")}
            <textarea name="egress" defaultValue={edit ? cur?.egress.map((e: any) => `${e.host}${e.pin ? ` ${e.pin}` : ""}`).join("\n") : ""} placeholder={"llm.garam.internal:443 sha256/Qm3…aF\napi.kftc.example:443 sha256/7Hc…02"} className="input mono mt-1 h-16 w-full text-xs" /></label>
          <div className="col-span-2 flex items-center gap-2">
            <button className="btn btn-primary">{edit ? tr(lang, "저장", "Save") : tr(lang, "대상 추가", "Add target")}</button>
            {edit && <Link className="btn btn-secondary" href={wizardHref("targets", p, t)}>{tr(lang, "취소", "Cancel")}</Link>}
            <span className="text-xs text-muted">{tr(lang, "대상 1개 이상 · 연결 시험 후 미리보기(③)로", "At least one target · test the connection, then go to preview (③)")}</span>
          </div>
        </form>
      )}
      {cur && <p className="mt-2 text-xs text-muted">{tr(lang, "등록", "Registered")} {LX(lang, cur.createdBy)} · {fmtTime(cur.createdAt)}</p>}
    </>
  );
}
