// CMP-12 즉시 사용 4단계 stepper — 프로파일 → 보호 대상 → 미리보기 → 적용 (선택값 p·t 는 쿼리로 다음 단계에 실어 보낸다).
import Link from "next/link";
import { type Lang, tr } from "@/lib/i18n";

const STEPS: [string, string, string][] = [["profiles", "프로파일", "Profile"], ["targets", "보호 대상", "Target"], ["preview", "미리보기", "Preview"], ["apply", "적용", "Apply"]];

export function wizardHref(step: string, p?: string, t?: string) {
  const q = new URLSearchParams();
  if (p) q.set("p", p);
  if (t) q.set("t", t);
  const s = q.toString();
  return `/instant/${step}${s ? `?${s}` : ""}`;
}

export function InstantSteps({ lang, at, p, t, next, nextOk = true, nextNote }: { lang: Lang; at: number; p?: string; t?: string; next?: string; nextOk?: boolean; nextNote?: string }) {
  return (
    <nav aria-label="instant steps" data-testid="instant-steps" className="card mb-4 flex items-center gap-2 p-3 text-sm">
      {STEPS.map(([id, ko, en], i) => (
        <span key={id} className="flex items-center gap-2">
          {i > 0 && <span className="text-muted">›</span>}
          <Link href={wizardHref(id, p, t)} aria-current={i + 1 === at ? "step" : undefined}
            className={`rounded-full px-3 py-1 ${i + 1 === at ? "bg-primary text-white" : i + 1 < at ? "bg-primary-soft text-primary" : "border border-line"}`}>
            {i + 1} {tr(lang, ko, en)}
          </Link>
        </span>
      ))}
      <span className="ml-3 text-xs text-muted">{at}/4 · {tr(lang, "목표 30분", "target 30 min")}{p ? ` · ${p}` : ""}{t ? ` → ${t}` : ""}</span>
      <span className="ml-auto flex items-center gap-2">
        {at > 1 && <Link className="btn btn-secondary h-8" href={wizardHref(STEPS[at - 2][0], p, t)}>‹ {tr(lang, "이전", "Back")}</Link>}
        {next && (nextOk ? <Link className="btn btn-primary h-8" data-testid="wizard-next" href={next}>{tr(lang, "다음", "Next")} ›</Link>
          : <span className="btn btn-primary h-8 opacity-50" aria-disabled title={nextNote}>{tr(lang, "다음", "Next")} ›</span>)}
      </span>
    </nav>
  );
}
