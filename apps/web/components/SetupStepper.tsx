// 첫 실행 단계 표시 (CMP-12) — 관리자·SSO → 신원·비밀 → 증적·관측 → 대상·첫 판정 → 검증, 설치 후 경과(30분 목표, NFR-O1).
import Link from "next/link";
import { api, safe } from "@/lib/api";

import { L, LX } from "@/lib/i18n";
import { prefs } from "@/lib/session";

export async function SetupStepper({ current }: { current: number }) {
  const { lang } = await prefs();
  const { data: st } = await safe(api("/v1/setup/status"), null as any);
  if (!st) return null;
  const over = st.minutesToFirstVerdict != null ? st.minutesToFirstVerdict > st.targetMin : st.elapsedMin > st.targetMin;
  return (
    <div className="card mb-4 flex items-center gap-3 p-3 text-sm" data-testid="stepper">
      {st.steps.map((x: any) => (
        <Link key={x.n} href={x.href} className={`flex items-center gap-2 rounded-full px-3 py-1 ${x.n === current ? "bg-primary text-white" : x.done ? "bg-primary-soft text-primary" : "border border-line"}`}>
          <span>{x.done ? "✓" : x.n}</span>{LX(lang, x.title)}
        </Link>
      ))}
      <span className="ml-auto text-xs" style={{ color: over ? "var(--verdict-block)" : undefined }}>{L(lang, "설치 후 ")}{LX(lang, st.elapsedMin ?? "—")}{L(lang, "분 · ")}{st.minutesToFirstVerdict != null ? L(lang, "첫 판정 {0}분", st.minutesToFirstVerdict) : L(lang, "첫 판정 전")}{L(lang, " · 목표 ")}{LX(lang, st.targetMin)}{L(lang, "분 (NFR-O1)")}</span>
    </div>
  );
}
