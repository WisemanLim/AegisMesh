// SCR-A03 도커 컴포즈·단일 호스트 설치 — local/prod 두 모드, make 타겟 수명주기.
import { PageHeader } from "@/components/Shell";
import { L, tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";

const STEPS: [string, string][] = [
  ["사전 점검", "make preflight            # Docker·Compose v2·env 파일"],
  ["local (SQLite · 개발)", "make local-all            # api·worker·web·otel-collector, 자동 마이그레이션·시드\nmake local-logs | grep 부트스트랩"],
  ["prod (PostgreSQL)", "cp .env.example .env.prod  # CHANGE_ME → 비밀 주입 (LEDGER/SVID 키·AUTH_SECRET·DB)\nmake prod-build && make db-migrate ENV=prod && make db-seed ENV=prod\nmake admin-token ENV=prod # 1회용 부트스트랩 토큰 → 콘솔 /setup"],
  ["검증", "make db-ping ENV=prod && curl -s 127.0.0.1:8000/health\nmake coverage"],
  ["갱신·정지", "git pull && make prod-build && make db-migrate ENV=prod   # 에이전트·정책은 무중단\nmake prod-stop"],
];

export default async function Compose() {
  const { lang } = await prefs();
  return (
    <>
      <PageHeader crumb={tr(lang, "설치 › 도커 컴포즈", "Install › Docker Compose")} title={tr(lang, "도커 컴포즈 · 단일 호스트 설치", "Docker Compose · single-host install")} />
      <div className="space-y-3">
        {STEPS.map(([t, c], i) => (
          <section key={t} className="card p-4 text-sm"><h2 className="mb-2 font-semibold">{i + 1}. {L(lang, t)}</h2><pre tabIndex={0} className="mono overflow-auto rounded bg-[#f6f7f9] p-3 text-[11px]">{L(lang, c)}</pre></section>
        ))}
      </div>
    </>
  );
}
