// SCR-A06 ② 조직 SSO(OIDC) — Issuer·Client ID·MFA 필수, IdP 그룹→역할 매핑(미매핑 거부), 연결 시험. 플랫폼 관리자 전용.
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { SsoTester } from "@/components/SsoTester";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { t, tr, LX } from "@/lib/i18n";
import { prefs } from "@/lib/session";
import { editMapping, saveSso } from "../actions";

import { L } from "@/lib/i18n";

const EV: Record<string, string> = { sso_login: "SSO 로그인", sso_denied: "SSO 거부", break_glass_login: "비상 관리자 로그인", sso_config: "설정 변경", sso_mappings: "매핑 변경", sso_test: "연결 시험" };

export default async function Sso({ searchParams }: { searchParams: Promise<{ msg?: string }> }) {
  const { lang } = await prefs();
  const { msg } = await searchParams;
  const [{ data: c, error }, { data: ten }] = await Promise.all([safe(api("/v1/auth/sso"), null as any), safe(api("/v1/tenants"), { items: [] as any[] })]);
  if (!c) return (<><PageHeader crumb={`${t(lang, "groupAdmin")} › ${t(lang, "sso")}`} title={tr(lang, "조직 SSO (OIDC)", "Organization SSO (OIDC)")} /><Banner tone="warn">{error ?? L(lang, "플랫폼 관리자 전용")}</Banner></>);
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupAdmin")} › ${t(lang, "sso")}`} title={tr(lang, "조직 SSO (OIDC)", "Organization SSO (OIDC)")} />
      {msg && <div className="mb-3"><Banner tone={msg.startsWith(L(lang, "실패")) ? "danger" : "info"}>{L(lang, msg)}</Banner></div>}
      <div className="grid grid-cols-2 gap-4">
        <form action={saveSso} className="card space-y-2 p-4 text-sm" data-testid="sso-config">
          <h2 className="font-semibold">{L(lang, "연결 ")}<Chip tone={c.enabled ? "primary" : "default"}>{c.enabled ? L(lang, "사용 중") : L(lang, "꺼짐")}</Chip> <span className="text-xs text-muted">{L(lang, "출처 ")}{LX(lang, c.source)}{c.updatedBy ? ` · ${c.updatedBy} ${fmtTime(c.updatedAt)}` : ""}</span></h2>
          <label className="block">Issuer URL<input name="issuer" defaultValue={c.issuer} required placeholder="https://sso.example/realms/corp" className="input mono mt-1 w-full" /></label>
          <div className="grid grid-cols-2 gap-2">
            <label className="block">Client ID<input name="clientId" defaultValue={c.clientId} required className="input mono mt-1 w-full" /></label>
            <label className="block">{L(lang, "그룹 클레임")}<input name="groupsClaim" defaultValue={c.groupsClaim} className="input mono mt-1 w-full" /></label>
          </div>
          <label className="flex items-center gap-2"><input type="checkbox" name="mfaRequired" defaultChecked={c.mfaRequired} />{L(lang, "MFA 필수 — 인정 acr")}<input name="acrValues" defaultValue={c.acrValues.join(", ")} className="input mono h-7 w-32" />{L(lang, " 또는 amr(otp·hwk·swk…)")}</label>
          <label className="flex items-center gap-2"><input type="checkbox" name="enabled" defaultChecked={c.enabled} />{L(lang, "사용 — 켜면 정적 비밀번호 로그인은 비상 관리자만(사유 필수)")}</label>
          <p className="text-xs text-muted">{L(lang, "인가 코드 + PKCE(S256) · ")}{c.clientSecret ? L(lang, "기밀 클라이언트(OIDC_CLIENT_SECRET)") : L(lang, "공개 클라이언트")}{L(lang, " · 서명 RS256 · 콜백 <콘솔>/auth/callback")}{c.backchannel ? L(lang, " · 백채널 주소 치환 사용") : ""}</p>
          <button className="btn btn-primary h-8 text-xs">{L(lang, "저장 (원장 기록)")}</button>
        </form>
        <section className="card space-y-2 p-4 text-sm" data-testid="sso-mappings">
          <h2 className="font-semibold">{L(lang, "그룹 → 역할 매핑")}</h2>
          <table className="grid-table text-xs"><thead><tr><th>{L(lang, "IdP 그룹")}</th><th>{L(lang, "AegisMesh 역할")}</th><th>{L(lang, "테넌트")}</th><th /></tr></thead>
            <tbody>{c.mappings.map((m: any, i: number) => (
              <tr key={`${m.group}-${m.role}-${m.tenant}`}><td className="mono">{LX(lang, m.group)}</td><td>{LX(lang, c.roles[m.role] ?? m.role)}</td><td>{LX(lang, m.tenant ?? L(lang, "플랫폼"))}</td>
                <td><form action={editMapping}><input type="hidden" name="drop" value={i} /><button className="btn btn-danger h-6 text-xs">{L(lang, "삭제")}</button></form></td></tr>))}</tbody></table>
          <form action={editMapping} className="flex items-end gap-2 text-xs">
            <label>{L(lang, "그룹")}<input name="group" required className="input mono mt-1 w-28" /></label>
            <label>{L(lang, "역할")}<select name="role" className="input mt-1">{Object.entries(c.roles).map(([k, v]) => <option key={k} value={k}>{L(lang, v as string)}</option>)}</select></label>
            <label>{L(lang, "테넌트")}<select name="tenant" className="input mt-1"><option value="">{L(lang, "플랫폼")}</option>{ten.items.map((x: any) => <option key={x.id} value={x.id}>{x.id}</option>)}</select></label>
            <button className="btn btn-secondary h-8 text-xs">{L(lang, "추가")}</button>
          </form>
          <p className="text-xs text-muted">{L(lang, "미매핑 사용자는 로그인 거부 · 로그인마다 IdP 그룹 기준으로 역할 동기화 · 매핑 해제 시 기존 세션 회수")}</p>
        </section>
        <section className="card p-4 text-sm"><h2 className="mb-2 font-semibold">{L(lang, "연결 시험")}</h2><SsoTester /></section>
        <section className="card p-4 text-sm"><h2 className="mb-2 font-semibold">{L(lang, "최근 SSO·비상 로그인")}</h2>
          <ul className="space-y-1 text-xs">{c.recent.length === 0 ? <li className="text-muted">{L(lang, "없음")}</li> : c.recent.map((e: any) => (
            <li key={e.seq} style={{ color: e.event === "sso_denied" || e.event === "break_glass_login" ? "var(--verdict-block)" : undefined }}>
              {fmtTime(e.at)} · {L(lang, EV[e.event] ?? e.event)} · {LX(lang, e.user ?? e.by)}{e.roles ? ` → ${e.roles.join(", ")}` : ""}{e.reason ? ` — ${L(lang, e.reason)}` : ""}</li>))}</ul></section>
      </div>
    </>
  );
}
