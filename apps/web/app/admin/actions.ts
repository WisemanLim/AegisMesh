"use server";
// 설정·관리 서버 액션 (SCR-R01·R02·B02) — 테넌트·사용자·역할·세션. 모든 변경은 API 가 원장에 남긴다.
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { ApiError, api } from "@/lib/api";

import { L } from "@/lib/i18n";
import { prefs } from "@/lib/session";

async function call(back: string, path: string, init: RequestInit, ok: (r: any) => string) {
  const { lang } = await prefs();
  let msg: string;
  try {
    msg = ok(await api(path, init));
  } catch (e) {
    msg = L(lang, "실패 {0}: {1}", e instanceof ApiError ? e.status : "", e instanceof ApiError ? (typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail)) : (e as Error).message);
  }
  revalidatePath("/", "layout");
  redirect(`${back}${back.includes("?") ? "&" : "?"}msg=${encodeURIComponent(msg)}`);
}

export async function addTenant(form: FormData) {
  const { lang } = await prefs();
  await call("/admin/tenants", "/v1/tenants", {
    method: "POST",
    body: JSON.stringify({ id: String(form.get("id")), name: String(form.get("name")), retentionDays: Number(form.get("retention") || 90), lang: String(form.get("lang") || "ko") }),
  }, (r) => L(lang, "테넌트 생성 {0} · 정책 {1} · 원장 {2}", r.id, r.namespaces.policy, r.namespaces.ledger));
}

export async function runIsolationTest() {
  const { lang } = await prefs();
  await call("/admin/tenants", "/v1/tenants:isolation-test", { method: "POST" }, (r) => L(lang, "교차 접근 시험 {0}/{1} {2}", r.passed, r.total, r.ok ? L(lang, "통과") : L(lang, "실패: {0}", r.failed.join(", "))));
}

export async function setTenantActive(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("id"));
  const active = String(form.get("active")) === "true";
  await call("/admin/tenants", `/v1/tenants/${id}`, { method: "PATCH", body: JSON.stringify({ active }) }, (r) => `${r.id}: ${r.active ? L(lang, "활성") : L(lang, "비활성")}`);
}

export async function addUser(form: FormData) {
  const { lang } = await prefs();
  const kind = String(form.get("kind") || "human");
  await call("/admin/users", "/v1/users", {
    method: "POST",
    body: JSON.stringify({
      username: String(form.get("username")), displayName: String(form.get("displayName") ?? ""), kind,
      roles: form.getAll("roles").map(String), tenant: String(form.get("tenant") || "") || null,
      password: kind === "human" ? String(form.get("password") ?? "") : null,
    }),
  }, (r) => L(lang, "사용자 생성 {0} ({1}) @ {2}", r.username, r.roles.join(", "), r.tenant ?? L(lang, "플랫폼")));
}

export async function saveRoles(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("id"));
  await call("/admin/users", `/v1/users/${id}`, { method: "PATCH", body: JSON.stringify({ roles: form.getAll("roles").map(String) }) },
    (r) => L(lang, "{0}: 역할 {1}", r.username, r.roles.join(", ")));
}

export async function deactivateUser(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("id"));
  await call("/admin/users", `/v1/users/${id}`, { method: "PATCH", body: JSON.stringify({ active: false }) }, (r) => L(lang, "{0}: 비활성 · 세션 전부 회수", r.username));
}

export async function activateUser(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("id"));
  await call("/admin/users", `/v1/users/${id}`, { method: "PATCH", body: JSON.stringify({ active: true }) }, (r) => L(lang, "{0}: 활성", r.username));
}

export async function revokeSession(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("id"));
  const back = String(form.get("back") || "/account");
  await call(back, `/v1/auth/sessions/${id}:revoke`, { method: "POST" }, (r) => L(lang, "세션 회수 {0}… ({1})", r.id.slice(0, 8), r.kind));
}

/** API 토큰 원문은 화면에 1회만 — URL·쿠키에 싣지 않고 액션 상태로 돌려준다. */
export async function issueToken(_prev: { token?: string; error?: string } | null, form: FormData) {
  try {
    const r = await api(`/v1/users/${String(form.get("id"))}/tokens`, {
      method: "POST", body: JSON.stringify({ name: String(form.get("name") || "token"), ttlDays: form.get("ttl") ? Number(form.get("ttl")) : null }),
    });
    return { token: r.token as string, id: r.id as string };
  } catch (e) {
    return { error: e instanceof ApiError ? String(e.detail) : (e as Error).message };
  }
}

export async function rotateIdentities(form: FormData) {
  const { lang } = await prefs();
  const force = String(form.get("force")) === "true";
  await call(String(form.get("back") || "/admin/identity"), "/v1/identity:rotate", { method: "POST", body: JSON.stringify({ force }) },
    (r) => force ? L(lang, "즉시 전체 회전 — SVID {0}개 무효화·재발급 {1} · 동적 시크릿 회수 {2}", r.invalidated, r.rotated, r.leasesRevoked) : L(lang, "정기 회전 {0}개", r.rotated));
}

export async function revokeLease(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("id"));
  await call("/admin/identity", `/v1/secrets/leases/${id}:revoke`, { method: "POST" }, (r) => L(lang, "임대 회수 {0} ({1})", r.id, r.path));
}

/** 동적 시크릿 원문은 1회만 — 액션 상태로 돌려준다(URL·쿠키에 싣지 않음). */
export async function issueLease(_prev: { secret?: string; error?: string } | null, form: FormData) {
  try {
    const r = await api("/v1/secrets/leases", {
      method: "POST",
      body: JSON.stringify({ path: String(form.get("path")), scopes: String(form.get("scopes")).split(",").map((x) => x.trim()).filter(Boolean),
        ttlSec: Number(form.get("ttl") || 300), tenant: String(form.get("tenant") || "") || null }),
    });
    return { secret: r.secret as string, id: r.id as string, expiresAt: r.expiresAt as string, path: r.path as string };
  } catch (e) {
    return { error: e instanceof ApiError ? String(e.detail) : (e as Error).message };
  }
}

export async function runSandboxProbe() {
  const { lang } = await prefs();
  await call("/admin/sandbox", "/v1/sandbox:probe", { method: "POST" },
    (r) => L(lang, "L1 탈출 점검 {0}/{1} 차단{2}", r.results.filter((x: any) => x.blocked).length, r.results.length, r.ok ? L(lang, " — 통과") : L(lang, " — 실패")));
}

export async function importBundle(form: FormData) {
  const { lang } = await prefs();
  const file = form.get("bundle");
  if (!(file instanceof File) || file.size === 0) redirect(`/admin/airgap?msg=${encodeURIComponent(L(lang, "실패: 번들 파일 선택"))}`);
  let msg: string;
  try {
    const r = await api("/v1/airgap/imports", { method: "POST", headers: { "content-type": "application/gzip" }, body: Buffer.from(await (file as File).arrayBuffer()) });
    msg = L(lang, "반입 완료 {0} · v{1} · {2}", r.id, r.version, r.steps.map((s: any) => s.step).join("→"));
  } catch (e) {
    const d = e instanceof ApiError ? (e.detail as any) : null;
    const bad = d?.steps?.find((s: any) => !s.ok);
    msg = L(lang, "실패: 반입 중단 — {0} {1}", bad?.step ?? "", bad?.detail ?? (e as Error).message);
  }
  revalidatePath("/", "layout");
  redirect(`/admin/airgap?msg=${encodeURIComponent(msg)}`);
}

export async function addTrustKey(form: FormData) {
  const { lang } = await prefs();
  await call("/admin/airgap", "/v1/trust-keys", {
    method: "POST", body: JSON.stringify({ keyId: String(form.get("keyId")), name: String(form.get("name")), publicKey: String(form.get("publicKey")).trim() }),
  }, (r) => L(lang, "신뢰 키 {0} 등록 요청 — 2인 승인 후 활성 ({1})", r.keyId, r.approvalRef));
}

export async function revokeTrustKey(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("keyId"));
  await call("/admin/airgap", `/v1/trust-keys/${id}:revoke`, { method: "POST", body: JSON.stringify({ reason: String(form.get("reason") || "폐기") }) },
    (r) => L(lang, "신뢰 키 {0} 폐기 요청 — 2인 승인 후 적용 ({1})", id, r.approvalRef));
}

export async function requestMarketInstall(form: FormData) {
  const { lang } = await prefs();
  const id = String(form.get("id"));
  await call("/marketplace", `/v1/market/${encodeURIComponent(id)}:request`, { method: "POST", body: JSON.stringify({}) },
    (r) => L(lang, "설치 요청 {0} — 승인 대기 ({1}) · 승인 후 등록 심사 R1~R5", r.listing, r.approvalRef));
}

// ── 조직 SSO (SCR-A06 ②) ─────────────────────────────────────
export async function saveSso(form: FormData) {
  const { lang } = await prefs();
  await call("/admin/sso", "/v1/auth/sso", {
    method: "PUT",
    body: JSON.stringify({
      issuer: String(form.get("issuer") ?? ""), clientId: String(form.get("clientId") ?? ""),
      groupsClaim: String(form.get("groupsClaim") || "groups"), mfaRequired: form.get("mfaRequired") === "on",
      acrValues: String(form.get("acrValues") ?? "").split(",").map((x) => x.trim()).filter(Boolean),
      enabled: form.get("enabled") === "on",
    }),
  }, (r) => L(lang, "SSO 설정 저장 — {0} · 원장 기록", r.enabled ? L(lang, "사용 (비밀번호 로그인은 비상 관리자만)") : L(lang, "꺼짐")));
}

export async function editMapping(form: FormData) {
  const { lang } = await prefs();
  const cur = (await api("/v1/auth/sso")).mappings as { group: string; role: string; tenant: string | null }[];
  const drop = form.get("drop");
  const items = drop != null
    ? cur.filter((_, i) => String(i) !== String(drop))
    : [...cur, { group: String(form.get("group") ?? "").trim(), role: String(form.get("role")), tenant: String(form.get("tenant") || "") || null }];
  await call("/admin/sso", "/v1/auth/sso/mappings", { method: "PUT", body: JSON.stringify({ items }) },
    (r) => L(lang, "그룹→역할 매핑 {0}건 — 원장 기록", r.mappings.length));
}

export async function testSso() {
  try {
    return { ok: true, data: await api("/v1/auth/sso:test", { method: "POST" }) };
  } catch (e) {
    return { ok: false, error: e instanceof ApiError ? `${e.status}: ${typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail)}` : (e as Error).message };
  }
}
