// SCR-C01 에이전트 카탈로그.
import Link from "next/link";
import { Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { standardChips } from "@/lib/format";
import { t, tr, nm, LX } from "@/lib/i18n";
import { prefs } from "@/lib/session";

import { L } from "@/lib/i18n";

export default async function Catalog() {
  const { lang } = await prefs();
  const { data, error } = await safe(api("/v1/agents"), { items: [] as any[] });
  return (
    <>
      <PageHeader crumb={t(lang, "catalog")} title={tr(lang, `에이전트 카탈로그 (${data.items.length}/92)`, `Agent catalog (${data.items.length}/92)`)} />
      {error && <p className="text-sm text-red-600">{error}</p>}
      <div className="card overflow-hidden">
        <table className="grid-table">
          <thead><tr><th>ID</th><th>{L(lang, "이름")}</th><th>{L(lang, "계열·관문")}</th><th>{L(lang, "격리")}</th><th>{L(lang, "강등")}</th><th>{L(lang, "표준")}</th><th>{L(lang, "상태")}</th></tr></thead>
          <tbody>
            {data.items.map((a: any) => (
              <tr key={a.id}>
                <td className="mono"><Link className="text-primary" href={`/catalog/${a.id}`}>{a.id}</Link></td>
                <td>{nm(lang, a)}{lang === "ko" && <div className="text-xs text-muted">{LX(lang, a.name)}</div>}</td>
                <td><Chip>{LX(lang, a.series)}</Chip> {LX(lang, a.gate)}</td>
                <td><Chip tone="primary">{LX(lang, a.isolation)}</Chip></td>
                <td>fail_{LX(lang, a.failMode)}</td>
                <td><div className="flex flex-wrap gap-1">{standardChips(a.standards).slice(0, 3).map((s) => <Chip key={s}>{s}</Chip>)}</div></td>
                <td>{LX(lang, a.status)}{a.origin === "api" && <div className="text-xs text-muted">{L(lang, "심사 R2~R5 대기")}</div>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
