// SCR-C08 프로파일 편집기 — YAML 편집 + 저장 전 검증(스키마·선택 결과·판정 값·지연 예산·격리·승인 필요 항목).
import { Banner } from "@/components/Badges";
import { ProfileEditor } from "@/components/PolicyLab";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { t } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";

import { L } from "@/lib/i18n";

const TEMPLATE = `apiVersion: aegismesh/v1
kind: Profile
metadata: {id: payments-guard, nameKo: 결제 에이전트 보호}
spec:
  extends: chatbot-baseline
  select:
    - {domain: [D3]}
    - {id: [D5-01, D6-03]}
  policyOverrides:
    D3-05: {verdict: block}
  evidence: {retentionDays: 365, payload: masked}
  region: {modelEgress: deny}
  defaultStage: partial
`;

export default async function ProfileEdit({ searchParams }: { searchParams: Promise<{ p?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const { p } = await searchParams;
  const base = p ? (await safe(api(`/v1/profiles/${encodeURIComponent(p)}`), null as any)).data : null;
  const initial = base ? base.yaml.replace(/id: [^,}\n]+/, `id: ${String(base.id).split(".").pop()}-custom`) : TEMPLATE;
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupMain")} › ${t(lang, "profileEditor")}`} title={base ? L(lang, "프로파일 편집기 — {0} 기반", base.id) : L(lang, "프로파일 편집기")} />
      {user?.scope === "*" && <div className="mb-3"><Banner tone="info">{L(lang, "사용자 정의 프로파일은 테넌트 범위에서 저장된다 — 상단에서 테넌트를 고르거나 기본 테넌트(default)에 저장.")}</Banner></div>}
      {!can(user, "policy.write") && <div className="mb-3"><Banner tone="info">{t(lang, "readOnly")}{L(lang, " — 검증만 가능.")}</Banner></div>}
      <ProfileEditor initial={initial} />
    </>
  );
}
