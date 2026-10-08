// SCR-R02 사용자·역할·접근 — 역할 부여(자기 역할 상향 불가), 서비스 계정 API 토큰, '이 사용자가 이 동작을 할 수 있는가' 확인.
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { TokenIssuer } from "@/components/TokenIssuer";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { t, tr, LX } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { activateUser, addUser, deactivateUser, saveRoles } from "../actions";

import { L } from "@/lib/i18n";

export default async function Users({ searchParams }: { searchParams: Promise<{ msg?: string; user?: string; perm?: string; tenant?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const sp = await searchParams;
  if (!can(user, "user.admin")) return <><PageHeader crumb={t(lang, "groupAdmin")} title={tr(lang, "사용자·역할·접근", "Users, roles & access")} /><Banner tone="info">{t(lang, "readOnly")}</Banner></>;
  const [users, roles, tenants] = await Promise.all([
    safe(api("/v1/users"), { items: [] as any[] }),
    safe(api("/v1/roles"), { roles: [] as any[], platformOnly: [] as string[] }),
    safe(api("/v1/tenants"), { items: [] as any[] }),
  ]);
  const check = sp.user && sp.perm
    ? await safe(api(`/v1/authz:check?${new URLSearchParams({ user: sp.user, perm: sp.perm, ...(sp.tenant ? { tenant: sp.tenant } : {}) })}`), null as any)
    : null;
  const assignable = roles.data.roles.filter((r: any) => user!.tenant === null || r.id !== "platform_admin");
  const perms: string[] = [...new Set<string>(roles.data.roles.flatMap((r: any) => r.permissions as string[]))].sort();
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupAdmin")} › ${t(lang, "users")}`} title={tr(lang, "사용자 · 역할 · 접근", "Users, roles & access")} />
      {sp.msg && <div className="mb-3"><Banner tone={sp.msg.startsWith(L(lang, "실패")) ? "danger" : "info"}>{L(lang, sp.msg)}</Banner></div>}
      <div className="grid grid-cols-[1fr_360px] gap-4">
        <div className="card overflow-hidden">
          <table className="grid-table">
            <thead><tr><th>{L(lang, "사용자")}</th><th>{L(lang, "역할")}</th><th>{L(lang, "테넌트")}</th><th>{L(lang, "최근 로그인")}</th><th>{L(lang, "상태·토큰")}</th></tr></thead>
            <tbody>
              {users.data.items.map((u: any) => (
                <tr key={u.id} className="align-top">
                  <td><b>{LX(lang, u.displayName)}</b><div className="mono text-xs text-muted">{LX(lang, u.username)}{u.kind === "service" ? L(lang, " · 서비스") : ""}{u.breakGlass ? L(lang, " · 비상") : ""}</div></td>
                  <td>
                    {u.kind === "service" || u.id === user!.id ? (
                      <div className="flex flex-wrap gap-1">{u.roles.map((r: string) => <Chip key={r}>{r}</Chip>)}{u.id === user!.id && <span className="text-xs text-muted">{L(lang, "자기 역할 변경 불가")}</span>}</div>
                    ) : (
                      <form action={saveRoles} className="flex flex-wrap items-center gap-1 text-xs">
                        <input type="hidden" name="id" value={u.id} />
                        {assignable.filter((r: any) => r.id !== "service" && (u.tenant === null || r.id !== "platform_admin")).map((r: any) => (
                          <label key={r.id} className="flex items-center gap-0.5" title={r.permissions.join(", ")}>
                            <input type="checkbox" name="roles" value={r.id} defaultChecked={u.roles.includes(r.id)} />{r.id}
                          </label>
                        ))}
                        <button className="btn btn-secondary h-6 text-xs">{L(lang, "저장")}</button>
                      </form>
                    )}
                  </td>
                  <td className="mono text-xs">{LX(lang, u.tenant ?? L(lang, "플랫폼"))}</td>
                  <td className="text-xs">{fmtTime(u.lastLoginAt)}{u.locked ? L(lang, " · 잠김") : ""}</td>
                  <td className="space-y-1">
                    {u.id !== user!.id && (
                      <form action={u.active ? deactivateUser : activateUser}>
                        <input type="hidden" name="id" value={u.id} />
                        <button className="btn btn-secondary h-6 text-xs">{u.active ? L(lang, "활성 · 비활성화") : L(lang, "비활성 · 활성화")}</button>
                      </form>
                    )}
                    {u.kind === "service" && u.active && <TokenIssuer userId={u.id} />}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="space-y-4">
          <form action={addUser} className="card space-y-2 p-4 text-sm">
            <h2 className="font-semibold">{L(lang, "+ 사용자 · 서비스 계정")}</h2>
            <input name="username" required placeholder={L(lang, "사용자 ID (소문자)")} className="input w-full" aria-label="username" />
            <input name="displayName" placeholder={L(lang, "표시 이름")} className="input w-full" aria-label="display name" />
            <select name="kind" className="input w-full" aria-label="kind" defaultValue="human">
              <option value="human">{L(lang, "사람 (로그인)")}</option><option value="service">{L(lang, "서비스 계정 (API 토큰만 · 판정 호출)")}</option>
            </select>
            {user!.tenant === null ? (
              <select name="tenant" className="input w-full" aria-label="tenant" defaultValue="">
                <option value="">{L(lang, "플랫폼 (모든 테넌트)")}</option>
                {tenants.data.items.map((x: any) => <option key={x.id} value={x.id}>{x.id} · {LX(lang, x.name)}</option>)}
              </select>
            ) : <p className="text-xs text-muted">{L(lang, "테넌트 ")}{LX(lang, user!.tenant)}{L(lang, " 에만 만든다")}</p>}
            <fieldset className="flex flex-wrap gap-x-3 gap-y-1 text-xs">
              <legend className="mb-1 text-muted">{L(lang, "역할 (서비스 계정은 무시)")}</legend>
              {assignable.filter((r: any) => r.id !== "service").map((r: any) => (
                <label key={r.id} className="flex items-center gap-1" title={r.permissions.join(", ")}><input type="checkbox" name="roles" value={r.id} />{LX(lang, r.name)}</label>
              ))}
            </fieldset>
            <input name="password" type="password" minLength={12} placeholder={L(lang, "초기 비밀번호 (사람, 12자 이상)")} className="input w-full" aria-label="password" autoComplete="new-password" />
            <button className="btn btn-primary w-full justify-center">{L(lang, "생성 (원장 기록)")}</button>
          </form>
          <form method="get" className="card space-y-2 p-4 text-sm">
            <h2 className="font-semibold">{L(lang, "권한 확인 — 이 사용자가 이 동작을?")}</h2>
            <input name="user" defaultValue={sp.user} required placeholder={L(lang, "사용자 ID")} className="input w-full" aria-label="check user" />
            <select name="perm" defaultValue={sp.perm ?? "approve"} className="input w-full" aria-label="permission">
              {perms.map((p) => <option key={p}>{p}</option>)}
            </select>
            <input name="tenant" defaultValue={sp.tenant} placeholder={L(lang, "대상 테넌트 (선택)")} className="input w-full" aria-label="check tenant" />
            <button className="btn btn-secondary w-full justify-center">{L(lang, "확인")}</button>
            {check && (check.error ? <p className="text-xs text-red-600">{LX(lang, check.error)}</p> : (
              <p className="text-xs" data-testid="authz-result"><b style={{ color: check.data.allowed ? "var(--verdict-allow)" : "var(--verdict-block)" }}>{check.data.allowed ? L(lang, "허용") : L(lang, "거부")}</b> · {LX(lang, check.data.reason)}</p>
            ))}
          </form>
          <Banner tone="info">{L(lang, "역할 8 유형 + 서비스 계정. 인가 판단은 API 의 단일 결정점에서만 · 자기 역할 상향 불가 · 모든 변경 원장 기록.")}</Banner>
        </div>
      </div>
    </>
  );
}
