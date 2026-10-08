// SCR-R03 신원·비밀 백엔드 — 워크로드 신원(SPIFFE JWT-SVID) 자동 발급·회전, 동적 시크릿 임대, 정적 자격증명 점검.
import { Banner, Chip } from "@/components/Badges";
import { LeaseIssuer } from "@/components/LeaseIssuer";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { t, tr, LX } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { revokeLease, revokeSession, rotateIdentities } from "../actions";

import { L } from "@/lib/i18n";

export default async function Identity({ searchParams }: { searchParams: Promise<{ msg?: string; kind?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const sp = await searchParams;
  const admin = can(user, "identity");
  const [st, leases, statics, cfg, bk] = await Promise.all([
    admin ? safe(api("/v1/identity"), null as any) : Promise.resolve({ data: null as any }),
    safe(api("/v1/secrets/leases"), { items: [] as any[] }),
    can(user, "user.admin") ? safe(api("/v1/identity/static-credentials"), { items: [] as any[] }) : Promise.resolve({ data: { items: [] as any[] } }),
    safe(api("/v1/auth/config", { token: null }), null as any),
    safe(api("/v1/secrets/backend"), null as any),
  ]);
  const b = bk.data;
  const s = st.data;
  const kind = sp.kind ?? "service";
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupAdmin")} › ${t(lang, "identity")}`} title={tr(lang, "신원 · 비밀 백엔드", "Identity & secrets backend")} />
      {sp.msg && <div className="mb-3"><Banner tone={sp.msg.startsWith(L(lang, "실패")) ? "danger" : "info"}>{L(lang, sp.msg)}</Banner></div>}
      <div className="grid grid-cols-3 gap-4">
        <section className="card p-4 text-sm" data-testid="identity-status">
          <h2 className="mb-2 font-semibold">{L(lang, "워크로드 신원 · SPIFFE (내장 발급자)")}</h2>
          {s ? (
            <ul className="space-y-1 text-xs">
              <li>{L(lang, "신뢰 도메인 ")}<b className="mono">{LX(lang, s.issuer)}</b></li>
              <li>{L(lang, "서명 ")}{LX(lang, s.algorithm)} · kid <span className="mono">{LX(lang, s.kid)}</span>{L(lang, " · 공개 번들 ")}<code className="mono">GET /v1/identity/jwks</code></li>
              <li>{L(lang, "SVID 에이전트 ")}{LX(lang, s.counts.agent)}{L(lang, " · 플랫폼 ")}{LX(lang, s.counts.platform)}{L(lang, " · 서비스 ")}{LX(lang, s.counts.service)}{L(lang, " — 유효 ")}{LX(lang, s.valid)}{L(lang, " · 미발급/만료 ")}{LX(lang, s.expired)}{L(lang, " · 폐기 ")}{LX(lang, s.revoked)}</li>
              <li>{L(lang, "수명 ")}{s.ttlSec / 3600}{L(lang, "시간 · 회전 ")}{LX(lang, s.rotateAt)}{L(lang, " 자동(worker) · 다음 ")}{fmtTime(s.nextRotation)}</li>
              <li>{L(lang, "최근 회전 ")}{s.lastRotation ? L(lang, "{0} · {1}개{2} · {3}", fmtTime(s.lastRotation.at), s.lastRotation.rotated, s.lastRotation.force ? L(lang, " (즉시 전체)") : "", s.lastRotation.by) : L(lang, "없음")}</li>
            </ul>
          ) : <p className="text-xs text-muted">{t(lang, "readOnly")}{L(lang, " — 플랫폼 보안 엔지니어·관리자")}</p>}
          {admin && (
            <div className="mt-3 flex gap-2">
              <form action={rotateIdentities}><input type="hidden" name="force" value="false" /><button className="btn btn-secondary h-8 text-xs">{L(lang, "정기 회전 실행")}</button></form>
              <form action={rotateIdentities}><input type="hidden" name="force" value="true" /><button className="btn btn-danger h-8 text-xs" title={L(lang, "사고 대응 — 모든 SVID 무효화 + 동적 시크릿 회수")}>{L(lang, "즉시 전체 회전")}</button></form>
            </div>
          )}
        </section>
        <section className="card p-4 text-sm">
          <h2 className="mb-2 font-semibold">{L(lang, "동적 시크릿 · 임대 발급 (최대 15분)")}</h2>
          {can(user, "secrets.lease") ? <LeaseIssuer tenants={user!.tenant ? [{ id: user!.tenant, name: user!.tenant }] : user!.tenants} /> : <p className="text-xs text-muted">{t(lang, "readOnly")}</p>}
          <p className="mt-2 text-xs text-muted">{L(lang, "호출 단위 토큰 다운스코핑 — 하위 도구는 ")}<code className="mono">POST /v1/secrets:introspect</code>{L(lang, " 로 범위·만료를 확인한다.")}</p>
          <p className="mt-1 text-xs" data-testid="lease-backend">{tr(lang, "임대 엔진: ", "Lease engine: ")}{b?.backend === "openbao"
            ? <><b>OpenBao {b.version ?? ""}</b> <span className="mono">{b.addr}</span> · {b.ok ? tr(lang, "정상 — 수명·갱신·회수·만료의 원본", "healthy — source of truth for lifetime, renewal, revocation and expiry")
              : b.sealed ? <span style={{ color: "var(--verdict-block)" }} data-testid="bao-sealed">{tr(lang, "봉인됨 — 봉인 해제(make bao-unseal) 전까지 발급·확인을 거부한다", "sealed — issuing and introspection are refused until unsealed (make bao-unseal)")}</span>
              : <span style={{ color: "var(--verdict-block)" }}>{tr(lang, "연결 불가 — 확인 요청은 거부된다(fail-closed)", "unreachable — introspection is refused (fail-closed)")} {b.error ?? ""}</span>}</>
            : <b>{tr(lang, "내장 브로커", "built-in broker")}</b>}</p>
          <div className="mt-2"><Banner tone="warn">{L(lang, "Vault 는 BUSL(비OSI) — 기본값 제외, 별도 프로세스·선택 연동만 (MSG-027)")}</Banner></div>
        </section>
        <section className="card p-4 text-sm">
          <h2 className="mb-2 font-semibold">{L(lang, "사용자 인증 · 외부 IdP")}</h2>
          <ul className="space-y-1 text-xs">
            <li>OIDC {cfg.data?.oidc?.enabled ? <Chip tone="primary">{L(lang, "연결 ")}{LX(lang, cfg.data.oidc.issuer)}</Chip> : <Chip>{L(lang, "미설정 (OIDC_ISSUER·OIDC_CLIENT_ID)")}</Chip>}</li>
            <li>{L(lang, "로컬 계정: 초기·비상·폐쇄망용 · 세션 ")}{LX(lang, cfg.data?.session?.ttlHours)}{L(lang, "시간 · 유휴 ")}{LX(lang, cfg.data?.session?.idleMinutes)}{L(lang, "분")}</li>
          </ul>
          <h2 className="mb-1 mt-3 font-semibold">{L(lang, "정적 자격증명 점검 (D5-01) — ")}{statics.data.items.length}{L(lang, "건")}</h2>
          {statics.data.items.length === 0 ? <p className="text-xs" style={{ color: "var(--verdict-allow)" }}>{L(lang, "서비스 계정 정적 API 키 잔존 0 ✓")}</p> : (
            <ul className="space-y-1 text-xs">{statics.data.items.map((x: any) => (
              <li key={x.token} className="flex items-center justify-between gap-2"><span><b>{LX(lang, x.user)}</b>@{LX(lang, x.tenant ?? L(lang, "플랫폼"))} · {LX(lang, x.name)}{L(lang, " · 만료 ")}{x.expiresAt ? fmtTime(x.expiresAt) : L(lang, "없음")}</span>
                <form action={revokeSession}><input type="hidden" name="id" value={x.token} /><input type="hidden" name="back" value="/admin/identity" /><button className="btn btn-danger h-6 text-xs">{L(lang, "폐기")}</button></form></li>
            ))}</ul>
          )}
          <p className="mt-1 text-xs text-muted">{L(lang, "권고: 서비스 계정은 SVID(1시간·자동 회전)로 호출 — ")}<code className="mono">POST /v1/identity/svid</code></p>
        </section>
      </div>
      <div className="mt-4 grid grid-cols-2 gap-4">
        <section className="card overflow-hidden text-sm">
          <div className="flex items-center gap-2 p-3"><h2 className="font-semibold">{L(lang, "워크로드 신원")}</h2>
            {["service", "platform", "agent"].map((k) => <a key={k} href={`/admin/identity?kind=${k}`} className={`rounded-full px-2 py-0.5 text-xs ${k === kind ? "bg-primary text-white" : "border border-line"}`}>{k}</a>)}</div>
          <table className="grid-table text-xs"><thead><tr><th>SPIFFE ID</th><th>{L(lang, "상태")}</th><th>{L(lang, "발급")}</th><th>{L(lang, "만료")}</th><th>{L(lang, "회전")}</th></tr></thead>
            <tbody>{(s?.items ?? []).filter((i: any) => i.kind === kind).slice(0, 40).map((i: any) => (
              <tr key={i.spiffeId}><td className="mono">{i.spiffeId.replace(/^spiffe:\/\/[^/]+/, "")}</td><td>{LX(lang, i.status)}</td><td>{fmtTime(i.issuedAt)}</td><td>{fmtTime(i.expiresAt)}</td><td>{LX(lang, i.rotations)}</td></tr>
            ))}</tbody></table>
        </section>
        <section className="card overflow-hidden text-sm">
          <h2 className="p-3 font-semibold">{L(lang, "동적 시크릿 임대")}</h2>
          <table className="grid-table text-xs"><thead><tr><th>{L(lang, "경로")}</th><th>{L(lang, "범위")}</th><th>{L(lang, "보유자")}</th><th>{L(lang, "만료")}</th><th>{L(lang, "상태")}</th><th>{tr(lang, "엔진", "Engine")}</th><th></th></tr></thead>
            <tbody>
              {leases.data.items.length === 0 && <tr><td colSpan={7} className="text-muted">{t(lang, "noData")}</td></tr>}
              {leases.data.items.slice(0, 30).map((l: any) => (
                <tr key={l.id}><td className="mono">{LX(lang, l.path)}</td><td>{l.scopes.join(", ")}</td><td className="mono max-w-[160px] truncate" title={l.holder}>{LX(lang, l.holder)}</td>
                  <td>{fmtTime(l.expiresAt)}{l.renewals ? ` (+${l.renewals})` : ""}</td><td><Chip tone={l.state === "active" ? "primary" : undefined}>{LX(lang, l.state)}</Chip></td><td>{l.backend === "openbao" ? "OpenBao" : tr(lang, "내장", "built-in")}{l.revokedBy === "openbao" ? tr(lang, " (OpenBao 회수)", " (revoked in OpenBao)") : ""}</td>
                  <td>{l.state === "active" && can(user, "secrets.lease") && <form action={revokeLease}><input type="hidden" name="id" value={l.id} /><button className="btn btn-secondary h-6 text-xs">{L(lang, "회수")}</button></form>}</td></tr>
              ))}
            </tbody></table>
        </section>
      </div>
    </>
  );
}
