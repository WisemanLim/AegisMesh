// 테넌트 로그인 정책 (OQ3) — 2단계 강제 범위(특권 역할 = 기본·끌 수 없음 / 전원)·인증기 AAGUID 허용목록.
import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { ApiError, api, safe } from "@/lib/api";
import { t as tk, tr } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";

async function save(form: FormData) {
  "use server";
  const tid = String(form.get("tenant"));
  const { lang } = await prefs();
  let msg: string;
  try {
    const aaguids = String(form.get("aaguids") ?? "").split(/[\s,]+/).filter(Boolean);
    await api(`/v1/tenants/${encodeURIComponent(tid)}/auth-policy`, { method: "PUT", body: JSON.stringify({ mfa: String(form.get("mfa")), aaguids }) });
    msg = tr(lang, "저장됨 — 다음 로그인부터 적용", "Saved — applies from the next sign-in");
  } catch (e) {
    msg = tr(lang, `실패 ${e instanceof ApiError ? `${e.status}: ${String(e.detail)}` : (e as Error).message}`, `Failed ${(e as Error).message}`);
  }
  revalidatePath("/admin/auth-policy");
  redirect(`/admin/auth-policy?tenant=${encodeURIComponent(tid)}&msg=${encodeURIComponent(msg)}`);
}

export default async function AuthPolicy({ searchParams }: { searchParams: Promise<{ tenant?: string; msg?: string }> }) {
  const { lang } = await prefs();
  const user = (await me())!;
  const sp = await searchParams;
  const tid = sp.tenant ?? user.tenant ?? (user.scope !== "*" ? user.scope : user.tenants[0]?.id ?? "default");
  const { data: p, error } = await safe(api(`/v1/tenants/${encodeURIComponent(tid)}/auth-policy`), null as any);
  const edit = can(user, "user.admin");
  return (
    <>
      <PageHeader crumb={`${tk(lang, "groupAdmin")} › ${tr(lang, "로그인 정책", "Sign-in policy")}`} title={tr(lang, `로그인 정책 — ${tid}`, `Sign-in policy — ${tid}`)} />
      {sp.msg && <div className="mb-3"><Banner tone={/^(실패|Failed)/.test(sp.msg) ? "danger" : "info"}>{sp.msg}</Banner></div>}
      {error && <p className="text-sm text-red-600">{error}</p>}
      {user.tenant === null && <form className="mb-3 flex items-center gap-2 text-sm"><select name="tenant" defaultValue={tid} className="input h-8" aria-label="tenant">{user.tenants.map((x) => <option key={x.id} value={x.id}>{x.id}</option>)}</select><button className="btn btn-secondary h-8">{tr(lang, "보기", "View")}</button></form>}
      {p && (
        <form action={save} className="card max-w-3xl space-y-3 p-4 text-sm" data-testid="auth-policy">
          <input type="hidden" name="tenant" value={tid} />
          <fieldset><legend className="mb-1 font-semibold">{tr(lang, "2단계 인증 강제", "Second-factor enforcement")}</legend>
            <label className="mr-4"><input type="radio" name="mfa" value="privileged" defaultChecked={p.mfa === "privileged"} disabled={!edit} /> {tr(lang, "특권 역할만 (기본)", "Privileged roles only (default)")}</label>
            <label><input type="radio" name="mfa" value="all" defaultChecked={p.mfa === "all"} disabled={!edit} /> {tr(lang, "이 테넌트 사용자 전원", "Every user in this tenant")}</label>
            <p className="mt-1 text-xs text-muted">{tr(lang, "특권 역할은 항상 필수:", "Always required for privileged roles:")} {p.privilegedRoles.map((r: string) => <Chip key={r}>{r}</Chip>)} · {tr(lang, "조직 SSO 로그인은 IdP 의 MFA 를 따른다 · 서비스 계정은 해당 없음", "SSO sign-ins follow the IdP's MFA · service accounts are exempt")}</p></fieldset>
          <label className="block"><span className="font-semibold">{tr(lang, "인증기 AAGUID 허용목록 (비우면 모두 허용)", "Authenticator AAGUID allowlist (empty = any)")}</span>
            <textarea name="aaguids" defaultValue={(p.aaguids ?? []).join("\n")} disabled={!edit} className="input mono mt-1 h-20 w-full text-xs" placeholder="cb69481e-8ff7-4039-93ec-0a2729a154a8" /></label>
          <p className="text-xs text-muted">{tr(lang, "허용목록이 있으면 등록 시 증명(direct)을 요청해 인증기가 밝힌 AAGUID 를 대조한다 — 증명 인증서 체인은 검증하지 않으므로 기종 보증이 아닌 정책 위생이다.", "With an allowlist, registration asks for direct attestation and checks the authenticator's self-reported AAGUID — the attestation certificate chain is not verified, so this is policy hygiene, not a model guarantee.")}</p>
          {edit && <button className="btn btn-primary">{tr(lang, "저장", "Save")}</button>}
        </form>
      )}
    </>
  );
}
