// SCR-A07 첫 실행 ② 신원·비밀 백엔드 — SVID 수명·회전, 비밀 백엔드, 정적 키 탐지·이관.
import Link from "next/link";
import { Banner, Chip } from "@/components/Badges";
import { SetupStepper } from "@/components/SetupStepper";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { tr, LX } from "@/lib/i18n";
import { prefs } from "@/lib/session";
import { revokeSession, rotateIdentities } from "@/app/admin/actions";

import { L } from "@/lib/i18n";

export default async function SetupIdentity({ searchParams }: { searchParams: Promise<{ msg?: string }> }) {
  const { lang } = await prefs();
  const { msg } = await searchParams;
  const [{ data: st }, { data: pre }, { data: statics }] = await Promise.all([safe(api("/v1/identity"), null as any), safe(api("/v1/install/precheck"), null as any),
    safe(api("/v1/identity/static-credentials"), { items: [] as any[] })]);
  const keys = pre?.checks.find((c: any) => c.id === "keys");
  return (
    <>
      <PageHeader crumb={tr(lang, "첫 실행 2/5", "First run 2/5")} title={tr(lang, "신원 · 비밀 백엔드", "Identity & secrets backend")} />
      <SetupStepper current={2} />
      {msg && <div className="mb-3"><Banner tone={msg.startsWith(L(lang, "실패")) ? "danger" : "info"}>{L(lang, msg)}</Banner></div>}
      <div className="grid grid-cols-2 gap-4">
        <section className="card p-4 text-sm"><h2 className="mb-2 font-semibold">{L(lang, "워크로드 신원 (SPIFFE JWT-SVID)")}</h2>
          {st ? <ul className="space-y-1 text-xs"><li>{L(lang, "신뢰 도메인 ")}<b className="mono">{LX(lang, st.issuer)}</b></li><li>{L(lang, "수명 ")}{st.ttlSec / 3600}{L(lang, "시간 · 회전 ")}{LX(lang, st.rotateAt)}{L(lang, " 자동")}</li>
            <li>{L(lang, "SVID 유효 ")}<b>{LX(lang, st.valid)}</b>{L(lang, " (에이전트 ")}{LX(lang, st.counts.agent)}{L(lang, " · 플랫폼 ")}{LX(lang, st.counts.platform)}{L(lang, " · 서비스 ")}{LX(lang, st.counts.service)})</li></ul> : <p className="text-xs text-muted">{L(lang, "권한 필요")}</p>}
          <form action={rotateIdentities} className="mt-2"><input type="hidden" name="force" value="false" /><input type="hidden" name="back" value="/setup/identity" /><button className="btn btn-secondary h-8 text-xs">{L(lang, "지금 발급·회전")}</button></form></section>
        <section className="card p-4 text-sm"><h2 className="mb-2 font-semibold">{L(lang, "비밀 백엔드")}</h2>
          <p className="text-xs">{L(lang, "내장 임대 브로커 사용 중 — 동적 시크릿 최대 15분·최소 범위·introspect. ")}<Chip>{L(lang, "OpenBao 미연결 (선택 연동)")}</Chip></p>
          <div className="mt-2"><Banner tone="warn">{L(lang, "Vault 는 BUSL(비OSI) — 기본값 제외 (MSG-027)")}</Banner></div></section>
        <section className="card col-span-2 p-4 text-sm" data-testid="static-keys"><h2 className="mb-2 font-semibold">{L(lang, "정적 키 탐지")}</h2>
          <p className="text-xs">{L(lang, "설치 설정의 서명 키: ")}{LX(lang, keys?.detail ?? "—")}</p>
          <ul className="mt-2 space-y-1 text-xs">{statics.items.length === 0 ? <li style={{ color: "var(--verdict-allow)" }}>{L(lang, "서비스 계정 정적 API 키 0 ✓")}</li> : statics.items.map((x: any) => (
            <li key={x.token} className="flex items-center justify-between"><span>{LX(lang, x.user)} · {LX(lang, x.name)}{L(lang, " · 만료 없음 — SVID(1시간)로 교체 후 폐기")}</span>
              <form action={revokeSession}><input type="hidden" name="id" value={x.token} /><input type="hidden" name="back" value="/setup/identity" /><button className="btn btn-danger h-6 text-xs">{L(lang, "폐기")}</button></form></li>))}</ul>
          <p className="mt-2 text-xs text-muted">{L(lang, "운영은 `LEDGER_SIGNING_KEY`·`SVID_SIGNING_KEY`·`AUTH_SECRET` 를 KMS·existingSecret 으로 주입 (볼륨 파일은 리허설용).")}</p></section>
      </div>
      <div className="mt-4 flex justify-between"><Link className="btn btn-secondary" href="/setup">{L(lang, "← 이전")}</Link><Link className="btn btn-primary" href="/setup/evidence">{L(lang, "다음 →")}</Link></div>
    </>
  );
}
