// SCR-C06 즉시 사용 ③ 판정 미리보기(재생) — 차단을 켜기 전에 표본을 선택 프로파일로 재생해 판정만 계산.
import { InstantSteps, wizardHref } from "@/components/InstantSteps";
import { Previewer } from "@/components/Previewer";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { t, tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";

export default async function Preview({ searchParams }: { searchParams: Promise<{ p?: string; t?: string }> }) {
  const { lang } = await prefs();
  const { p, t: target } = await searchParams;
  const [{ data }, { data: tr_ }] = await Promise.all([safe(api("/v1/profiles"), { items: [] as any[] }),
    safe(api(`/v1/traffic-samples?limit=1${target ? `&target=${encodeURIComponent(target)}` : ""}`), null as any)]);
  return (
    <>
      <PageHeader crumb={`${t(lang, "instant")} › ${t(lang, "preview")}`} title={tr(lang, "판정 미리보기 — 차단 전에 재생", "Verdict preview — replay before blocking")} />
      <InstantSteps lang={lang} at={3} p={p} t={target} next={wizardHref("apply", p, target)} nextOk={!!p && !!target}
        nextNote={tr(lang, "① 프로파일 · ② 보호 대상을 먼저 고른다", "Choose a profile (①) and a target (②) first")} />
      <Previewer key={p} initial={p} target={target} traffic={tr_ ? { enabled: tr_.settings.enabled, total: tr_.total } : undefined}
        profiles={data.items.map((x: any) => ({ id: x.id, nameKo: x.nameKo }))} />
    </>
  );
}
