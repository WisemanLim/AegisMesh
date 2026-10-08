// SCR-A01 설치 안내·사전 점검 — 배포 형태 선택(쿠버네티스·도커 컴포즈·단일 호스트·CLI) + 현재 설치 실측 점검.
import Link from "next/link";
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { tr, LX } from "@/lib/i18n";
import { prefs } from "@/lib/session";

import { L } from "@/lib/i18n";

const FORMS = [
  { href: "/install/helm", ko: "쿠버네티스 (헬름)", en: "Kubernetes (Helm)", desc: "운영 권장 — api·worker·web·수집기·PostgreSQL, 롤링 갱신, existingSecret 으로 키 주입" },
  { href: "/install/compose", ko: "도커 컴포즈 · 단일 호스트", en: "Docker Compose · single host", desc: "local(SQLite)·prod(PostgreSQL) 두 모드, make 타겟으로 수명주기" },
  { href: "/install/cli", ko: "CLI (aegis) · M1 독립 실행", en: "CLI (aegis) · M1 standalone", desc: "플랫폼 없이 에이전트 1종 — 단일 파일 바이너리, REST·MCP·A2A 상주" },
];

export default async function Install() {
  const { lang } = await prefs();
  const { data: p, error } = await safe(api("/v1/install/precheck"), null as any);
  return (
    <>
      <PageHeader crumb={tr(lang, "설치·첫 실행", "Install & first run")} title={tr(lang, "설치 안내 · 사전 점검", "Install guide · pre-check")} />
      <div className="mb-4 grid grid-cols-3 gap-3">
        {FORMS.map((f) => (
          <Link key={f.href} href={f.href} className={`card p-4 text-sm hover:border-primary ${p && ((p.form === "kubernetes" && f.href.endsWith("helm")) || (p.form !== "kubernetes" && f.href.endsWith("compose"))) ? "border-primary" : ""}`}>
            <b>{tr(lang, f.ko, f.en)}</b><p className="mt-1 text-xs text-muted">{L(lang, f.desc)}</p>
          </Link>
        ))}
      </div>
      {error && <Banner tone="danger">{error}</Banner>}
      {p && (
        <section className="card p-4 text-sm" data-testid="precheck">
          <h2 className="mb-2 font-semibold">{tr(lang, `사전 점검 — 현재 배포 ${p.form} · ${p.env}`, `Pre-check — ${p.form} · ${p.env}`)} <Chip tone={p.ok ? "primary" : undefined}>{LX(lang, p.passed)}/{p.total}</Chip></h2>
          <table className="grid-table text-xs"><thead><tr><th>{L(lang, "점검")}</th><th>{L(lang, "결과")}</th><th>{L(lang, "근거")}</th><th>{L(lang, "구분")}</th></tr></thead>
            <tbody>{p.checks.map((c: any) => (
              <tr key={c.id}><td>{LX(lang, c.title)}</td><td style={{ color: c.ok ? "var(--verdict-allow)" : c.level === "required" ? "var(--verdict-block)" : "#9d6105" }}>{c.ok ? "✓" : "✗"}</td><td>{LX(lang, c.detail)}</td><td>{c.level === "required" ? L(lang, "필수") : L(lang, "권고")}</td></tr>
            ))}</tbody></table>
          <p className="mt-2 text-xs text-muted">{L(lang, "첫 판정 ")}{p.firstVerdictAt ? fmtTime(p.firstVerdictAt) : L(lang, "아직 없음")}{L(lang, " · 다음 단계: ")}<Link className="text-primary" href="/setup/identity">{L(lang, "첫 실행 마법사")}</Link> · <Link className="text-primary" href="/setup/verify">{L(lang, "설치 검증")}</Link></p>
        </section>
      )}
    </>
  );
}
