"use client";
// 학습 데이터 재현 시험 (SCR-F04, D2-05) — 모델 출력 표본(빈 줄 또는 --- 로 구분)을 D2-05 로 판정해 추출률·배포 게이트. 표본은 저장하지 않는다.
import { useActionState } from "react";
import { recallRun } from "@/app/domains/actions";
import { tr } from "@/lib/i18n";
import { useLang } from "@/lib/lang";

export function RecallForm() {
  const lang = useLang();
  const [s, action, pending] = useActionState(recallRun, null);
  return (
    <form action={action} className="space-y-2 text-xs" data-testid="recall-form">
      <div className="grid grid-cols-2 gap-2">
        <input name="model" required className="input" placeholder={tr(lang, "모델 (예 loan-review-ft)", "Model (e.g. loan-review-ft)")} aria-label="model" />
        <input name="version" required className="input" placeholder={tr(lang, "버전 (예 v3)", "Version (e.g. v3)")} aria-label="version" />
      </div>
      <textarea name="outputs" required className="input mono h-28 w-full" aria-label="outputs"
        placeholder={tr(lang, "모델 출력 표본 — 빈 줄 또는 --- 로 구분 (저장하지 않음)", "Model output samples — separated by blank lines or --- (not stored)")} />
      <div className="grid grid-cols-3 gap-2">
        <input name="miaAuc" className="input" inputMode="decimal" placeholder={tr(lang, "멤버십 추론 AUC (외부 시험, 선택)", "MIA AUC (external, optional)")} aria-label="miaAuc" />
        <input name="dpEpsilon" className="input" inputMode="decimal" placeholder={tr(lang, "차등 프라이버시 ε (선택)", "DP ε (optional)")} aria-label="dpEpsilon" />
        <input name="dedupRate" className="input" inputMode="decimal" placeholder={tr(lang, "중복 제거율 0~1 (선택)", "Dedup rate 0–1 (optional)")} aria-label="dedupRate" />
      </div>
      <button className="btn btn-primary" disabled={pending}>{tr(lang, "시험 실행 → 배포 게이트", "Run test → release gate")}</button>
      {s && !s.ok && <p role="alert" className="text-red-600">{s.error}</p>}
      {s?.ok && (
        <p data-testid="recall-result">{s.data.model} {s.data.version}: {tr(lang, "추출률", "extraction")} {(s.data.extractionRate * 100).toFixed(2)}% ({s.data.flagged}/{s.data.samples})
          {s.data.miaAuc != null && ` · AUC ${s.data.miaAuc}`} → <b style={{ color: s.data.gate === "pass" ? "var(--verdict-allow)" : "var(--verdict-block)" }}>{s.data.gate === "pass" ? tr(lang, "배포 게이트 통과", "release gate passed") : tr(lang, "배포 차단 (MSG-021)", "release blocked (MSG-021)")}</b>
          {s.data.reasons.length > 0 && ` — ${s.data.reasons.join("; ")}`} · {tr(lang, `원장 #${s.data.seq}`, `ledger #${s.data.seq}`)}</p>
      )}
    </form>
  );
}
