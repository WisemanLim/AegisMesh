"use client";
// CMP-04 판정 배지 · CMP-05 심각도 배지 · CMP-09 표준 매핑 칩 — 색은 의미로만, 글자 병기. 언어는 LangProvider(쿠키 lang).
import { L } from "@/lib/i18n";
import { useLang } from "@/lib/lang";

const VERDICT: Record<string, [string, string]> = {
  allow: ["허용", "var(--verdict-allow)"],
  block: ["차단", "var(--verdict-block)"],
  require_approval: ["승인 요구", "var(--verdict-approval)"],
  transform: ["무해화", "var(--verdict-transform)"],
  alert: ["경보", "var(--verdict-alert)"],
};
const SEV: Record<string, string> = {
  info: "var(--sev-info)", low: "var(--sev-low)", medium: "var(--sev-medium)", high: "var(--sev-high)", critical: "var(--sev-critical)",
};

export function VerdictBadge({ v }: { v: string }) {
  const lang = useLang();
  const [ko, color] = VERDICT[v] ?? [v, "var(--muted)"];
  const label = L(lang, ko);
  return (
    <span className="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold text-white" style={{ background: color }}>
      {label} <span className="ml-1 font-normal">{v}</span>
    </span>
  );
}

export function SeverityBadge({ s }: { s: string }) {
  return (
    <span className="inline-flex items-center rounded px-1.5 py-0.5 text-xs font-semibold" style={{ color: SEV[s] ?? "var(--muted)", border: `1px solid ${SEV[s] ?? "var(--line)"}` }}>
      {s}
    </span>
  );
}

export function Chip({ children, tone = "default" }: { children: React.ReactNode; tone?: "default" | "primary" }) {
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs ${tone === "primary" ? "bg-primary-soft text-primary" : "bg-[#f0f2f6] text-ink"}`}>
      {children}
    </span>
  );
}

export function Banner({ tone, children }: { tone: "info" | "warn" | "danger"; children: React.ReactNode }) {
  const c = { info: ["#e8f6f4", "#257a6e"], warn: ["#fff6e6", "#9d6105"], danger: ["#fdecec", "#c03333"] }[tone];
  return (
    <div role={tone === "danger" ? "alert" : "status"} className="rounded-lg px-4 py-2.5 text-sm" style={{ background: c[0], color: c[1], border: `1px solid ${c[1]}33` }}>
      {children}
    </div>
  );
}

export function Kpi({ label, value, sub, accent }: { label: string; value: React.ReactNode; sub?: React.ReactNode; accent: string }) {
  return (
    <div className="card p-4" style={{ borderLeft: `4px solid ${accent}` }}>
      <div className="text-xs text-muted">{label}</div>
      <div className="mt-1 text-2xl font-bold">{value}</div>
      {sub && <div className="mt-1 text-xs text-muted">{sub}</div>}
    </div>
  );
}
