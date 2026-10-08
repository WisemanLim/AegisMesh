// SCR-D05 판정 시뮬레이터 (what-if) — 실제 차단·기록 없이 합성 판정·근거, 초안 vs 배포 정책 비교.
import { Simulator } from "@/components/PolicyLab";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { t, tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";

const SAMPLE = JSON.stringify({ tool: { name: "transfer_funds", args: { amount: 5000 } }, subject: { principal: { id: "user.sim" } } }, null, 2);

export default async function Simulate() {
  const { lang } = await prefs();
  const { data } = await safe(api("/v1/policies/default/versions"), { items: [] as any[] });
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupGates")} › ${t(lang, "simulate")}`} title={tr(lang, "판정 시뮬레이터 — 차단·기록 없이 미리 보기", "Verdict simulator — preview without blocking or recording")} />
      <Simulator draft={data.items[0]?.yaml ?? ""} sample={SAMPLE} />
    </>
  );
}
