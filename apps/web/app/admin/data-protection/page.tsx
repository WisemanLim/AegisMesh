// SCR-R06 데이터 보호·보존·국외 이전 — 원문 미보존, 보존기간, 수집 단계 마스킹, 외부 모델 호출, 암호화 키 출처.
import Link from "next/link";
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { t, tr, LX } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { fmtTime } from "@/lib/format";
import { clearSamples, saveSampleRetention } from "./actions";

import { L } from "@/lib/i18n";

export default async function DataProtection({ searchParams }: { searchParams: Promise<{ msg?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const { msg } = await searchParams;
  const [{ data: d, error }, { data: sm }] = await Promise.all([safe(api("/v1/data-protection"), null as any),
    can(user, "quality") ? safe(api("/v1/traffic-samples?limit=8"), null as any) : safe(api("/v1/traffic-samples/settings").then((x) => ({ settings: x, total: null, items: [] })), null as any)]);
  const priv = can(user, "privacy");
  if (!d) return <><PageHeader crumb={t(lang, "groupAdmin")} title={tr(lang, "데이터 보호", "Data protection")} /><Banner tone="danger">{error}</Banner></>;
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupAdmin")} › ${t(lang, "dataProtection")}`} title={tr(lang, "데이터 보호 · 보존 · 국외 이전", "Data protection · retention · cross-border")} />
      {msg && <div className="mb-3"><Banner tone={/^(실패|Failed)/.test(msg) ? "danger" : "info"}>{msg}</Banner></div>}
      <div className="grid grid-cols-2 gap-4" data-testid="data-protection">
        <section className="card p-4 text-sm"><h2 className="mb-2 font-semibold">{tr(lang, "판정 페이로드", "Verdict payload")}</h2>
          <p><Chip tone="primary">{d.payload.stored ? L(lang, "보존") : L(lang, "미보존(기본)")}</Chip> {LX(lang, d.payload.policy)}</p><p className="mt-1 text-xs text-muted">{LX(lang, d.payload.enable)}</p></section>
        <section className="card p-4 text-sm"><h2 className="mb-2 font-semibold">{tr(lang, "보존기간·삭제 전파", "Retention & deletion")}</h2>
          <p className="text-xs">{L(lang, "기본 ")}{LX(lang, d.retention.default)}{L(lang, "일 · ")}{d.retention.tenants.map((x: any) => L(lang, "{0} {1}일({2})", x.id, x.retentionDays, x.region)).join(" · ")} · <Link className="text-primary" href="/admin/tenants">{L(lang, "테넌트별 설정")}</Link></p>
          <p className="mt-1 text-xs text-muted">{LX(lang, d.retention.deletion)}</p></section>
        <section className="card p-4 text-sm"><h2 className="mb-2 font-semibold">{tr(lang, "지표·추적·로그", "Telemetry")}</h2>
          <p className="text-xs">{L(lang, "수집 단계 마스킹 규칙 ")}{LX(lang, d.telemetry.masking)}{L(lang, "종 (")}{d.telemetry.rules.join(", ")}{L(lang, ") · 수집기 ")}{LX(lang, d.telemetry.endpoint ?? L(lang, "미설정"))} · <Link className="text-primary" href="/observability">{L(lang, "관측")}</Link></p></section>
        <section className="card p-4 text-sm"><h2 className="mb-2 font-semibold">{tr(lang, "외부 모델 호출(국외 이전)", "External model calls")}</h2>
          <p className="text-xs">{L(lang, "설정 ")}<b>{LX(lang, d.egress.setting)}</b>{L(lang, " · 적용 프로파일 정책 ")}{d.egress.profiles.join(", ") || "—"}</p><p className="mt-1 text-xs text-muted">{LX(lang, d.egress.note)}</p></section>
        {sm && <section className="card col-span-2 p-4 text-sm" data-testid="sample-retention">
          <h2 className="mb-2 font-semibold">{tr(lang, "미리보기 표본 보존 (OQ1) — 기본 미보존, 켜면 수집 단계 마스킹", "Preview samples (OQ1) — off by default, masked at capture when on")}</h2>
          <p className="text-xs">{sm.settings.enabled ? <Chip tone="primary">{tr(lang, `보존 중 — 최근 ${sm.settings.maxSamples}건·${sm.settings.days}일`, `On — latest ${sm.settings.maxSamples} · ${sm.settings.days} days`)}</Chip> : <Chip>{tr(lang, "미보존(기본)", "Off (default)")}</Chip>}
            {sm.total != null && <span className="ml-2 text-muted">{tr(lang, `보관 ${sm.total}건`, `${sm.total} stored`)}</span>}
            <span className="ml-2 text-muted">{tr(lang, "마스킹: 주민번호·카드·이메일·전화·API 키·토큰 + 주체 가명화, 인증·세션 값 제거", "Masking: RRN, card, e-mail, phone, API keys, tokens + pseudonymous principals; auth and session values dropped")}</span></p>
          {priv && <form action={saveSampleRetention} className="mt-2 flex flex-wrap items-center gap-3 text-xs" data-testid="sample-form">
            <label className="flex items-center gap-1"><input type="checkbox" name="enabled" defaultChecked={sm.settings.enabled} />{tr(lang, "보존", "Keep samples")}</label>
            <label>{tr(lang, "최대 건수", "Max samples")} <input name="maxSamples" type="number" min={10} max={10000} defaultValue={sm.settings.maxSamples} className="input h-7 w-24" /></label>
            <label>{tr(lang, "기간(일)", "Days")} <input name="days" type="number" min={1} max={30} defaultValue={sm.settings.days} className="input h-7 w-16" /></label>
            <button className="btn btn-primary h-7 text-xs">{tr(lang, "저장 (켜기·확대 = 2인 승인)", "Save (on / widen = two approvals)")}</button>
          </form>}
          {priv && sm.total > 0 && <form action={clearSamples} className="mt-1"><button className="btn btn-secondary h-6 text-xs">{tr(lang, "표본 전부 삭제", "Delete all samples")}</button></form>}
          {sm.items?.length > 0 && <table className="grid-table mt-2 text-xs" data-testid="sample-list"><thead><tr><th>{tr(lang, "시각", "Time")}</th><th>{tr(lang, "관문 · 대상", "Gate · target")}</th><th>{tr(lang, "판정", "Verdict")}</th><th>{tr(lang, "마스킹된 요청", "Masked request")}</th><th>{tr(lang, "마스킹", "Masked")}</th><th>{tr(lang, "라벨", "Label")}</th></tr></thead>
            <tbody>{sm.items.map((x: any) => <tr key={x.id}><td>{fmtTime(x.createdAt)}</td><td>{x.gate} · {x.target ?? "—"}</td><td>{x.verdict}</td>
              <td className="mono max-w-[420px] truncate" title={x.request.text ?? ""}>{x.request.text ?? JSON.stringify(x.request).slice(0, 80)}</td><td>{x.masked.join(", ") || "—"}</td><td>{x.label ?? "—"}</td></tr>)}</tbody></table>}
          <p className="mt-1 text-xs text-muted">{tr(lang, "미리보기(C06)에서 '실제 트래픽' 으로 재생·라벨 → 오탐 추정. 끄면 즉시 전부 삭제, 만료·초과분은 worker 가 지운다. 변경은 원장(privacy)에 남는다.", "Replay and label them as 'real traffic' in preview (C06) to estimate false positives. Turning off deletes everything; the worker removes expired and excess samples. Changes are recorded in the ledger (privacy).")}</p>
        </section>}
        <section className="card col-span-2 p-4 text-sm"><h2 className="mb-2 font-semibold">{tr(lang, "암호화·서명 키", "Keys")}</h2>
          <ul className="space-y-1 text-xs">{d.keys.map((k: any) => <li key={k.name}><b>{LX(lang, k.name)}</b> — {LX(lang, k.source)}</li>)}</ul>
          <p className="mt-1 text-xs text-muted">{L(lang, "운영은 외부 키 관리(KMS·OpenBao)에서 주입한다 (.env.prod CHANGE_ME → 주입).")}</p></section>
      </div>
    </>
  );
}
