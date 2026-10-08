// SCR-A08 첫 실행 ③ 증적 원장·관측 — 보존 기간·체크포인트, 원문 보존·외부 모델 호출(기본 꺼짐), 수집 단계 마스킹.
import Link from "next/link";
import { Banner, Chip } from "@/components/Badges";
import { SetupStepper } from "@/components/SetupStepper";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { tr, LX } from "@/lib/i18n";
import { prefs } from "@/lib/session";
import { setRetention } from "../actions";

import { L } from "@/lib/i18n";

export default async function SetupEvidence({ searchParams }: { searchParams: Promise<{ msg?: string }> }) {
  const { lang } = await prefs();
  const { msg } = await searchParams;
  const [{ data: dp }, { data: obs }] = await Promise.all([safe(api("/v1/data-protection"), null as any), safe(api("/v1/observability"), null as any)]);
  const cur = dp?.retention.tenants.find((t: any) => t.id === "default")?.retentionDays ?? 90;
  return (
    <>
      <PageHeader crumb={tr(lang, "첫 실행 3/5", "First run 3/5")} title={tr(lang, "증적 원장 · 관측 저장소", "Evidence ledger & telemetry")} />
      <SetupStepper current={3} />
      {msg && <div className="mb-3"><Banner tone={msg.startsWith(L(lang, "실패")) ? "danger" : "info"}>{L(lang, msg)}</Banner></div>}
      <div className="grid grid-cols-2 gap-4">
        <form action={setRetention} className="card space-y-2 p-4 text-sm" data-testid="retention"><h2 className="font-semibold">{L(lang, "증적 보존 기간 (기본 테넌트)")}</h2>
          {[[90, "90일 — 기본"], [365, "1년"], [1825, "5년 — regulated-kr (전자금융·개인정보)"]].map(([d, l]) => (
            <label key={d} className="flex items-center gap-2 text-xs"><input type="radio" name="days" value={d} defaultChecked={cur === d} />{L(lang, String(l))}</label>))}
          <button className="btn btn-primary h-8 text-xs">{L(lang, "저장 (원장 기록)")}</button>
          <p className="text-xs text-muted">{L(lang, "추가 전용 해시 체인 · 서명 체크포인트 · 만료는 승인된 배치로만 (MSG-016)")}</p></form>
        <section className="card space-y-2 p-4 text-sm"><h2 className="font-semibold">{L(lang, "원문·국외 이전")}</h2>
          <p className="text-xs">{L(lang, "판정 원문 보존 ")}<Chip>{L(lang, "꺼짐 (기본, NFR-D1)")}</Chip>{L(lang, " · 외부 모델 호출 ")}<Chip>{LX(lang, dp?.egress.setting ?? "deny")}</Chip></p>
          <p className="text-xs text-muted">{L(lang, "바꾸려면 승인 필요 — 이 설치에는 원문 저장 기능이 없다.")}</p></section>
        <section className="card col-span-2 p-4 text-sm"><h2 className="mb-2 font-semibold">{L(lang, "관측 파이프라인 (OpenTelemetry)")}</h2>
          {obs ? <p className="text-xs">{L(lang, "수집기 ")}{LX(lang, obs.endpoint ?? L(lang, "미설정"))}{L(lang, " · 처리 ")}{Object.values(obs.pipeline)[0] ? (Object.values(obs.pipeline)[0] as any).processors.join(" → ") : "—"}{L(lang, " · 마스킹 규칙 ")}{obs.masking.length}{L(lang, "종 · 전송 성공 ")}{LX(lang, obs.stats.traces.ok)}</p> : <p className="text-xs text-muted">—</p>}
          <p className="mt-1 text-xs"><Link className="text-primary" href="/observability">{L(lang, "관측·마스킹 시험 로그")}</Link></p></section>
      </div>
      <div className="mt-4 flex justify-between"><Link className="btn btn-secondary" href="/setup/identity">{L(lang, "← 이전")}</Link><Link className="btn btn-primary" href="/setup/first-verdict">{L(lang, "다음 →")}</Link></div>
    </>
  );
}
