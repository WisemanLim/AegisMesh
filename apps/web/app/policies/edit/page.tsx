// SCR-D04 정책 편집기·단위 시험·배포 — 시험 실패 시 배포 차단, 배포는 관문에 즉시 반영.
import { Banner } from "@/components/Badges";
import { PolicyEditor } from "@/components/PolicyLab";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { t } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";

import { L } from "@/lib/i18n";

const TEMPLATE = `apiVersion: aegismesh/v1
kind: Policy
metadata: {id: default}
spec:
  minConfidence: 0.5
  partialBlockConfidence: 0.9
  overrides: {}
tests:
  - name: 고위험 이체는 승인
    gate: tool
    agents: [d3-01]
    request: {tool: {name: transfer_funds, args: {amount: 5000}}}
    expect: require_approval
`;

export default async function PolicyEdit({ searchParams }: { searchParams: Promise<{ p?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const { p = "default" } = await searchParams;
  const { data } = await safe(api(`/v1/policies/${encodeURIComponent(p)}/versions`), { items: [] as any[] });
  const initial = data.items[0]?.yaml ?? TEMPLATE;
  return (
    <>
      <PageHeader crumb={L(lang, "{0} › {1} › 편집기", t(lang, "groupGates"), t(lang, "policies"))} title={L(lang, "정책 편집기 — {0}{1}", p, data.items[0] ? L(lang, " (v{0} 기준)", data.items[0].version) : "")} />
      {!can(user, "policy.write") && <div className="mb-3"><Banner tone="info">{t(lang, "readOnly")}{L(lang, " — 단위 시험·배포는 정책 쓰기 권한이 필요하다.")}</Banner></div>}
      <PolicyEditor initial={initial.includes("tests:") ? initial : `${initial}${initial.endsWith("\n") ? "" : "\n"}tests: []\n`} />
    </>
  );
}
