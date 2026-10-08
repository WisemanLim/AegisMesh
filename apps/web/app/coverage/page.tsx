// SCR-Q03 일부 — 누락 검증(DP10, FR-P16): CI 의 verify_coverage.py 와 같은 판정.
import Link from "next/link";
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { t, tr, LX } from "@/lib/i18n";
import { prefs } from "@/lib/session";

import { L } from "@/lib/i18n";

export default async function Coverage() {
  const { lang } = await prefs();
  const { data, error } = await safe(api("/v1/coverage"), null as any);
  if (!data) return <p className="text-red-600">{error}</p>;
  const s = data.strict;
  return (
    <>
      <PageHeader crumb={t(lang, "coverage")} title={tr(lang, "도식 대비 커버리지 — 누락은 빌드 실패", "Diagram coverage — gaps fail the build")} />
      <div className="mb-4">
        <Banner tone={s.failures.length ? "danger" : "info"}>{L(lang, "엄격 범위(1단계 P0) ")}{LX(lang, s.implemented)}/{s.total}{L(lang, " · 전체 ")}{LX(lang, data.implemented)}/{data.total} — {s.failures.length ? L(lang, "CI 실패") : L(lang, "CI 통과")}
        </Banner>
      </div>
      <div className="card overflow-hidden">
        <table className="grid-table">
          <thead><tr><th>{L(lang, "항목")}</th><th>{L(lang, "우선")}</th><th>{L(lang, "단계")}</th><th>{L(lang, "범위")}</th><th>{L(lang, "에이전트")}</th><th>{L(lang, "상태")}</th></tr></thead>
          <tbody>
            {data.items.map((i: any) => (
              <tr key={i.id}>
                <td className="mono"><Link className="text-primary" href={`/risk-map?item=${i.id}`}>{i.id}</Link></td>
                <td>{LX(lang, i.priority)}</td><td>{LX(lang, i.stage)}</td><td>{i.strict ? <Chip tone="primary">{L(lang, "엄격")}</Chip> : <Chip>{L(lang, "보고")}</Chip>}</td>
                <td className="mono">{LX(lang, i.agent ?? "—")}</td>
                <td className="text-xs">{i.implemented ? L(lang, "✓ 구현") : i.errors.join("; ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
