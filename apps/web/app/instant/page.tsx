// SCR-C04 프로파일 선택 · SCR-C05 대상 · SCR-C07 적용 단계·해제 (즉시 사용 M3).
import Link from "next/link";
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { t, tr, nm, LX } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { applyProfile, releaseApplication } from "./actions";

import { L } from "@/lib/i18n";

const STAGES = [["observe", "차단 없이 관측만"], ["partial", "부분 차단 (고신뢰만)"], ["enforce", "전체 차단"]];

export default async function Instant({ searchParams }: { searchParams: Promise<{ msg?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const { msg } = await searchParams;
  const ro = !can(user, "policy.write");
  const [profiles, apps] = await Promise.all([
    safe(api("/v1/profiles"), { items: [] as any[] }),
    safe(api("/v1/applications"), { items: [] as any[] }),
  ]);
  return (
    <>
      <PageHeader crumb={t(lang, "instant")} title={tr(lang, "즉시 사용 — 프로파일 선택 → 대상 → 적용 단계", "Instant use — profile → target → stage")}
        actions={<Link className="btn btn-primary" href="/instant/profiles" data-testid="wizard-start">{tr(lang, "4단계 마법사 시작 ›", "Start the 4-step wizard ›")}</Link>} />
      {msg && <div className="mb-4"><Banner tone={msg.startsWith(L(lang, "실패")) ? "danger" : "info"}>{L(lang, msg)}</Banner></div>}
      <div className="grid grid-cols-5 gap-3">
        {profiles.data.items.map((p: any) => (
          <form key={p.id} action={applyProfile} className="card flex flex-col gap-2 p-4 text-sm">
            <input type="hidden" name="profile" value={p.id} />
            <div className="font-bold">{nm(lang, p)}</div>
            <div className="mono text-xs text-muted">{p.id}{p.extends ? ` ⊃ ${p.extends}` : ""} {p.custom && <Chip>{L(lang, "사용자 정의")}</Chip>}
              <Link className="ml-1 text-primary" href={`/profiles/edit?p=${p.id}`}>{L(lang, "복제·편집")}</Link></div>
            <div className="flex flex-wrap gap-1">
              <Chip tone="primary">{L(lang, "항목 ")}{LX(lang, p.items)}</Chip><Chip>{L(lang, "구현 ")}{LX(lang, p.available)}</Chip><Chip>{L(lang, "미구현 ")}{LX(lang, p.missing)}</Chip>
            </div>
            <div className="text-xs">{L(lang, "차단 정책: ")}{LX(lang, p.blocking)}</div>
            <div className="text-xs text-muted">{L(lang, "예상 지연: ")}{LX(lang, p.expectedLatency)}</div>
            <input name="target" required placeholder={L(lang, "보호 대상 (예 chat.garam.example)")} className="input text-xs" aria-label="target" />
            <select name="stage" defaultValue={p.defaultStage} className="input text-xs" aria-label="stage">
              {STAGES.map(([v, l]) => <option key={v} value={v}>{L(lang, l)}</option>)}
            </select>
            <button className="btn btn-primary justify-center" disabled={ro || p.available === 0} title={ro ? t(lang, "readOnly") : undefined}>
              {t(lang, "apply")}
            </button>
          </form>
        ))}
      </div>
      <h2 className="mb-2 mt-6 font-semibold">{L(lang, "활성 적용")}</h2>
      <div className="card overflow-hidden">
        <table className="grid-table">
          <thead><tr><th>ID</th><th>{L(lang, "프로파일")}</th><th>{L(lang, "대상")}</th><th>{L(lang, "단계")}</th><th>{L(lang, "에이전트")}</th><th>{L(lang, "미구현")}</th><th>{L(lang, "적용자·시각")}</th><th /></tr></thead>
          <tbody>
            {apps.data.items.length === 0 && <tr><td colSpan={8} className="text-muted">{t(lang, "noData")}</td></tr>}
            {apps.data.items.map((a: any) => (
              <tr key={a.id}>
                <td className="mono">{a.id}</td><td>{LX(lang, a.profile)}</td><td>{LX(lang, a.target)}</td><td><Chip tone="primary">{LX(lang, a.stage)}</Chip></td>
                <td>{a.agents.length}</td><td>{a.missing.length}</td><td>{LX(lang, a.appliedBy)}<div className="text-xs text-muted">{fmtTime(a.appliedAt)}</div></td>
                <td>
                  <form action={releaseApplication}>
                    <input type="hidden" name="id" value={a.id} />
                    <button className="btn btn-danger" disabled={ro} title={ro ? t(lang, "readOnly") : undefined}>{t(lang, "release")}</button>
                  </form>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-3 text-xs text-muted">{L(lang, "미리보기 재생(SCR-C06)은 원문 미보존(NFR-D1) 기본값과 충돌해 후속 설계 대상이다.")}</p>
    </>
  );
}
