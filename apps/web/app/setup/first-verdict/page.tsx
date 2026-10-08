// SCR-A09 첫 실행 ④ 보호 대상·프로파일·첫 판정 — 기본 minimal-visibility, 첫 판정까지 경과(30분 목표).
import Link from "next/link";
import { FirstVerdict } from "@/components/FirstVerdict";
import { SetupStepper } from "@/components/SetupStepper";
import { PageHeader } from "@/components/Shell";
import { tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";

import { L } from "@/lib/i18n";

export default async function SetupFirstVerdict() {
  const { lang } = await prefs();
  return (
    <>
      <PageHeader crumb={tr(lang, "첫 실행 4/5", "First run 4/5")} title={tr(lang, "보호 대상 · 프로파일 · 첫 판정", "Target · profile · first verdict")} />
      <SetupStepper current={4} />
      <FirstVerdict />
      <div className="mt-4 flex justify-between"><Link className="btn btn-secondary" href="/setup/evidence">{L(lang, "← 이전")}</Link><Link className="btn btn-primary" href="/setup/verify">{L(lang, "다음 →")}</Link></div>
    </>
  );
}
