// SCR-B02 ②·③ 내 계정 — 2단계 인증 수단(패스키 우선·OTP 대체), 내 세션(기기·위치·DPoP 바인딩·상태, 개별·일괄 종료), 세션 정책·탈취 대응.
import Link from "next/link";
import { cookies } from "next/headers";
import { Banner, Chip } from "@/components/Badges";
import { PasskeyButton } from "@/components/Passkey";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { TOTP_COOKIE, unseal } from "@/lib/dpop";
import { fmtTime } from "@/lib/format";
import { t, tr, LX } from "@/lib/i18n";
import { me, prefs } from "@/lib/session";
import { revokeSession } from "../admin/actions";
import { deletePasskey, registerPasskey, revokeOthers, totpConfirm, totpDisable, totpSetup } from "./actions";

const ST: Record<string, [string, string, string]> = { active: ["활성", "active", "var(--verdict-allow)"], review: ["검토 — 재인증 필요", "review — re-auth needed", "#9d6105"],
  idle: ["유휴 만료", "idle", "var(--sev-info)"], expired: ["만료", "expired", "var(--sev-info)"], revoked: ["종료", "revoked", "var(--sev-info)"] };

export default async function Account({ searchParams }: { searchParams: Promise<{ msg?: string; add?: string; totp?: string }> }) {
  const { lang } = await prefs();
  const user = (await me())!;
  const sp = await searchParams;
  const [{ data }, { data: m }] = await Promise.all([safe(api("/v1/auth/sessions"), { items: [] as any[] }), safe(api("/v1/auth/mfa"), null as any)]);
  const reg = sp.add === "passkey" ? await safe(api("/v1/auth/webauthn/register:options", { method: "POST" }), null as any) : null;
  const totpNew = sp.totp === "setup" ? unseal<{ secret: string; uri: string }>((await cookies()).get(TOTP_COOKIE)?.value) : null;
  const sessions = (data.items as any[]).filter((x) => x.kind === "session");
  const others = sessions.filter((x) => !x.current && (x.state === "active" || x.state === "review")).length;
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupAdmin")} › ${t(lang, "account")}`} title={`${user.displayName} (${user.username})`} />
      {sp.msg && <div className="mb-3"><Banner tone={/^(실패|Failed)/.test(sp.msg) ? "danger" : "info"}>{LX(lang, sp.msg)}</Banner></div>}
      {user.breakGlass && <div className="mb-3"><Banner tone="danger">{tr(lang, "비상(break-glass) 계정 — 평상시 봉인. 사용 기록은 원장에 남는다.", "Break-glass account — sealed in normal operation. Every use is recorded in the ledger.")}</Banner></div>}
      {m && m.methods.length === 0 && <div className="mb-3"><Banner tone="warn">{tr(lang, "2단계 인증 수단 없음 — 보안 키·패스키를 등록한다 (FR-D5-01)", "No second factor — register a security key or passkey (FR-D5-01)")}</Banner></div>}
      <div className="grid grid-cols-[1fr_360px] gap-4">
        <div className="space-y-4">
          <section className="card overflow-hidden text-sm" data-testid="sessions">
            <div className="flex items-center gap-2 p-3">
              <h2 className="font-semibold">{tr(lang, "③ 내 세션 — 기기·위치·바인딩", "③ My sessions — device · location · binding")}</h2>
              {others > 0 && <form action={revokeOthers} className="ml-auto"><button className="btn btn-secondary h-7 text-xs" data-testid="revoke-others">{tr(lang, `다른 세션 종료 (${others})`, `End other sessions (${others})`)}</button></form>}
            </div>
            <table className="grid-table text-xs">
              <thead><tr><th>{tr(lang, "기기", "Device")}</th><th>{tr(lang, "위치 · IP 대역", "Location · IP range")}</th><th>{tr(lang, "바인딩", "Binding")}</th><th>{tr(lang, "2단계", "2nd factor")}</th><th>{tr(lang, "시작 · 최근", "Started · last")}</th><th>{tr(lang, "상태", "Status")}</th><th /></tr></thead>
              <tbody>{sessions.length === 0 ? <tr><td colSpan={7} className="text-muted">—</td></tr> : sessions.map((x) => (
                <tr key={x.id} style={x.state === "review" ? { background: "#fdf3e6" } : undefined}>
                  <td>◆ {x.device ?? (x.name || "—")}{x.current ? <b> {tr(lang, "(현재)", "(this)")}</b> : null}</td><td>{x.geo === "private" ? tr(lang, "사설망", "Private network") : x.geo === "unknown" ? tr(lang, "위치 미확인", "Unknown location") : x.geo ?? "—"}<div className="mono text-muted">{x.location ?? "—"}</div></td>
                  <td>{x.dpop ? <Chip tone="primary">DPoP</Chip> : <span className="text-muted">bearer</span>}</td><td>{x.mfa ?? "—"}</td>
                  <td>{fmtTime(x.createdAt)}<div className="text-muted">{fmtTime(x.lastSeenAt)}</div></td>
                  <td><b style={{ color: ST[x.state]?.[2] }}>{tr(lang, ...(ST[x.state] ?? [x.state, x.state]).slice(0, 2) as [string, string])}</b>{x.reviewReason ? <div className="text-muted">{x.reviewReason}</div> : null}</td>
                  <td>{(x.state === "active" || x.state === "review") && !x.current && (
                    <form action={revokeSession}><input type="hidden" name="id" value={x.id} /><input type="hidden" name="back" value="/account" />
                      <button className="btn btn-secondary h-6 text-xs">{tr(lang, "종료", "End")}</button></form>)}</td>
                </tr>))}</tbody>
            </table>
          </section>
          <section className="card p-4 text-sm" data-testid="mfa-methods">
            <h2 className="mb-2 font-semibold">{tr(lang, "② 2단계 인증 — 보안 키·패스키 우선 · 인증 앱 OTP 대체", "② Second factor — security key / passkey first · authenticator-app OTP fallback")}
              {m?.required && <Chip tone="primary">{tr(lang, "필수 (특권 역할·테넌트 정책)", "required (privileged role · tenant policy)")}</Chip>} <a className="text-xs font-normal text-primary" href="/admin/auth-policy">{tr(lang, "로그인 정책 ›", "Sign-in policy ›")}</a></h2>
            <table className="grid-table text-xs"><thead><tr><th>{tr(lang, "수단", "Method")}</th><th>{tr(lang, "이름", "Name")}</th><th>{tr(lang, "등록", "Added")}</th><th>{tr(lang, "최근 사용", "Last used")}</th><th /></tr></thead>
              <tbody>
                {(m?.webauthn ?? []).map((c: any) => (
                  <tr key={c.id}><td>{tr(lang, "패스키·보안 키", "Passkey / key")} <span className="text-muted">{c.alg}</span></td><td>{c.name}</td><td>{fmtTime(c.createdAt)}</td><td>{fmtTime(c.lastUsedAt)}</td>
                    <td><form action={deletePasskey}><input type="hidden" name="id" value={c.id} /><button className="btn btn-secondary h-6 text-xs">{tr(lang, "삭제", "Remove")}</button></form></td></tr>))}
                {m?.totp && <tr><td>{tr(lang, "인증 앱 OTP", "Authenticator OTP")}</td><td>TOTP · 30s · 6</td><td>—</td><td>—</td><td><form action={totpDisable}><button className="btn btn-secondary h-6 text-xs">{tr(lang, "해제", "Remove")}</button></form></td></tr>}
                {!m?.webauthn?.length && !m?.totp && <tr><td colSpan={5} className="text-muted">{tr(lang, "등록된 수단 없음", "Nothing enrolled")}</td></tr>}
              </tbody></table>
            <div className="mt-3 grid grid-cols-2 gap-3">
              <div>
                {reg?.data ? (
                  <PasskeyButton mode="create" publicKey={reg.data.publicKey} action={registerPasskey} fields={{ ticket: reg.data.ticket }} needName testId="passkey-register"
                    namePlaceholder={tr(lang, "이름 (예: MacBook Touch ID)", "Name (e.g. MacBook Touch ID)")} label={tr(lang, "등록", "Register")} busyLabel={tr(lang, "보안 키 터치 대기…", "Waiting for the key…")} className="btn btn-primary h-8 text-xs" />
                ) : <Link className="btn btn-primary h-8 text-xs" href="/account?add=passkey" data-testid="passkey-add">{tr(lang, "+ 보안 키·패스키 추가", "+ Add security key / passkey")}</Link>}
              </div>
              <div>
                {totpNew ? (
                  <form action={totpConfirm} className="space-y-1 text-xs" data-testid="totp-setup">
                    <div>{tr(lang, "인증 앱에 추가 (이 화면에서만 보인다):", "Add to your authenticator app (shown only here):")}</div>
                    <code className="mono block break-all rounded bg-line/40 p-1" data-testid="totp-secret">{totpNew.secret}</code>
                    <a className="text-primary" href={totpNew.uri}>otpauth://…</a>
                    <div className="flex gap-1"><input name="code" required pattern="[0-9]{6}" inputMode="numeric" autoComplete="one-time-code" className="input mono h-7 flex-1" placeholder="123456" aria-label="otp code" /><button className="btn btn-secondary h-7">{tr(lang, "확인", "Confirm")}</button></div>
                  </form>
                ) : !m?.totp && <form action={totpSetup}><button className="btn btn-secondary h-8 text-xs" data-testid="totp-start">{tr(lang, "인증 앱 OTP 등록", "Set up authenticator OTP")}</button></form>}
              </div>
            </div>
          </section>
        </div>
        <div className="card space-y-2 p-4 text-sm">
          <h2 className="font-semibold">{tr(lang, "내 권한", "My permissions")}</h2>
          <div className="flex flex-wrap gap-1">{user.roles.map((r) => <Chip key={r} tone="primary">{LX(lang, user.roleNames[r] ?? r)}</Chip>)}</div>
          <p className="text-xs text-muted">{tr(lang, "테넌트 ", "Tenant ")}{LX(lang, user.tenant ?? tr(lang, "플랫폼(모든 테넌트)", "platform (all tenants)"))}{tr(lang, " · 현재 범위 ", " · scope ")}{LX(lang, user.scope)}</p>
          <div className="flex flex-wrap gap-1">{user.permissions.map((p) => <Chip key={p}>{p}</Chip>)}</div>
          <h2 className="pt-2 font-semibold">{tr(lang, "세션 정책", "Session policy")}</h2>
          <table className="grid-table text-xs" data-testid="session-policy"><tbody>
            <tr><td className="text-muted">{tr(lang, "수명", "Lifetime")}</td><td>{tr(lang, "8시간", "8 h")}</td></tr>
            <tr><td className="text-muted">{tr(lang, "유휴 만료", "Idle expiry")}</td><td>{tr(lang, "30분", "30 min")}</td></tr>
            <tr><td className="text-muted">{tr(lang, "토큰", "Token")}</td><td>{user.binding?.dpop ? tr(lang, "DPoP 소유 증명 바인딩 ✓", "DPoP proof-of-possession bound ✓") : tr(lang, "bearer (바인딩 없음)", "bearer (unbound)")}</td></tr>
            <tr><td className="text-muted">{tr(lang, "재사용 감지", "Reuse detection")}</td><td>{tr(lang, "켬 · 즉시 폐기", "on · revoke at once")}</td></tr>
            <tr><td className="text-muted">{tr(lang, "기록", "Records")}</td><td>{tr(lang, "증적 원장", "evidence ledger")}</td></tr>
          </tbody></table>
          <ul className="list-disc pl-4 text-xs text-muted">
            <li>{tr(lang, "로그인 5회 실패(2단계 포함) 시 15분 잠금", "5 failed sign-ins (incl. second step) lock for 15 min")}</li>
            <li>{tr(lang, "새 위치(다른 나라·100 km 밖, 지오 없으면 IP 대역)·기기 감지 → 재인증 요구 (MSG-030)", "New location (another country or 100 km+, IP range without geo) or device → re-authentication (MSG-030)")}</li>
            <li>{tr(lang, "불가능한 이동(500 km 이상을 시속 900 km 넘게) → 재인증·경보", "Impossible travel (500 km or more faster than 900 km/h) → re-authentication + alert")}</li>
            <li><a className="text-primary" href="https://db-ip.com" rel="noopener noreferrer" target="_blank">IP Geolocation by DB-IP</a> (CC BY 4.0)</li>
            <li>{tr(lang, "탈취 토큰 재사용(증명 없음·다른 키·증명 재사용) → 세션 전체 폐기·사건 (FR-D5-03)", "Stolen-token reuse (no proof · other key · replayed proof) → all sessions revoked + incident (FR-D5-03)")}</li>
          </ul>
          <form action="/logout" method="post"><button className="btn btn-danger w-full justify-center">{t(lang, "logout")}</button></form>
        </div>
      </div>
    </>
  );
}
