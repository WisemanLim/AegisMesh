// 서버 전용 API 클라이언트 — 서버 컴포넌트·서버 액션에서만 호출한다(브라우저 → API 직접 호출 없음, CORS 불필요).
// 로그인 세션 토큰은 httpOnly 쿠키에만 두고, 여기서 Authorization 으로 옮겨 싣는다(브라우저 JS 는 토큰을 볼 수 없다).
import "server-only";
import type { JsonWebKey } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import https from "node:https";
import { cookies, headers as reqHeaders } from "next/headers";
import { DPOP_COOKIE, proof, unseal } from "@/lib/dpop";

export const BASE = process.env.API_URL ?? "http://127.0.0.1:8000";
export const SESSION_COOKIE = "aegis_session";
export const TENANT_COOKIE = "aegis_tenant";

// prod 내부 상호 TLS (NFR-D3) — API_TLS_DIR 의 내부 CA 로 api 서버 인증서를 검증하고 콘솔 클라이언트 인증서를 낸다.
// 인증서가 회전되면(mtime 변화) 다음 연결부터 새 인증서를 쓴다 — 콘솔 재기동 없음. local 은 평문 fetch.
const TLS_DIR = process.env.API_TLS_DIR;
let tlsAgent: { agent: https.Agent; mtime: number } | null = null;

function agent(): https.Agent {
  const mtime = statSync(`${TLS_DIR}/tls.crt`).mtimeMs;
  if (!tlsAgent || tlsAgent.mtime !== mtime) {
    tlsAgent?.agent.destroy();
    tlsAgent = { mtime, agent: new https.Agent({ keepAlive: true, ca: readFileSync(`${TLS_DIR}/ca.crt`),
                                                 cert: readFileSync(`${TLS_DIR}/tls.crt`), key: readFileSync(`${TLS_DIR}/tls.key`) }) };
  }
  return tlsAgent.agent;
}

/** API 호출용 fetch — https 면 상호 TLS(Node https, 응답은 표준 Response 로 감싼다), 아니면 전역 fetch. */
export function apiFetch(url: string, init: RequestInit = {}): Promise<Response> {
  if (!TLS_DIR || !url.startsWith("https:")) return fetch(url, init);
  return new Promise((resolve, reject) => {
    const req = https.request(url, { method: init.method ?? "GET", headers: init.headers as Record<string, string>, agent: agent() }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("error", reject);
      res.on("end", () => {
        const headers = new Headers();
        for (const [k, v] of Object.entries(res.headers)) for (const x of [v ?? []].flat()) headers.append(k, String(x));
        const status = res.statusCode ?? 502;
        resolve(new Response([204, 205, 304].includes(status) ? null : Buffer.concat(chunks), { status, headers }));
      });
    });
    req.on("error", reject);
    if (init.body != null) req.write(init.body as string);
    req.end();
  });
}

export class ApiError extends Error {
  constructor(public status: number, public detail: unknown) {
    super(`API ${status}: ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
  }
}

/** 브라우저 쪽 IP·UA — API 는 DPoP 로 묶인 세션(이 서버가 키 보관)일 때만 이 값으로 새 기기·위치를 본다 (MSG-030). */
async function clientHeaders(): Promise<Record<string, string>> {
  try {
    const h = await reqHeaders();
    const ip = (h.get("x-forwarded-for") ?? "").split(",")[0].trim() || h.get("x-real-ip") || "";
    return { ...(ip ? { "X-Aegis-Client-IP": ip } : {}), "X-Aegis-Client-UA": (h.get("user-agent") ?? "").slice(0, 300) };
  } catch {
    return {};
  }
}

/** API 호출 헤더 — 세션 토큰 · 테넌트 범위 · DPoP 증명(세션이 키에 묶였으면) · 브라우저 IP·UA. dpopKey 는 로그인 계열(토큰 전) 요청용. */
export async function authHeaders(method: string, path: string, token?: string | null, dpopKey?: JsonWebKey | null): Promise<Record<string, string>> {
  const jar = await cookies();
  let tok = token === undefined ? jar.get(SESSION_COOKIE)?.value : token;
  const tenant = jar.get(TENANT_COOKIE)?.value;
  const sealed = token === undefined ? jar.get(DPOP_COOKIE)?.value : undefined;
  const key = dpopKey ?? (tok && sealed ? unseal<JsonWebKey>(sealed) : null);
  // 묶인 세션인데 키를 못 열면(콘솔 재기동·봉인 키 변경) 토큰을 싣지 않는다 — 증명 없는 바인딩 토큰은 API 가 탈취로 보고 전체 폐기한다
  if (tok && sealed && !key) tok = undefined;
  return {
    ...(tok ? { Authorization: `Bearer ${tok}` } : {}),
    ...(tok && tenant ? { "X-Aegis-Tenant": tenant } : {}),
    ...(key ? { DPoP: proof(key, method, `${BASE}${path}`, tok) } : {}),
    ...(await clientHeaders()),
  };
}

/** token: 생략 = 세션 쿠키, null = 익명(로그인·부트스트랩). dpopKey: 로그인·2단계·SSO 콜백에서 새 세션을 묶을 키. */
export async function api<T = any>(path: string, init: RequestInit & { token?: string | null; dpopKey?: JsonWebKey | null } = {}): Promise<T> {
  const { token, headers, dpopKey, ...rest } = init;
  const res = await apiFetch(`${BASE}${path}`, {
    cache: "no-store",
    ...rest,
    headers: {
      "content-type": "application/json",
      ...(await authHeaders(String(rest.method ?? "GET"), path, token, dpopKey)),
      ...headers,
    },
  });
  const body = res.headers.get("content-type")?.includes("json") ? await res.json() : await res.text();
  if (!res.ok) throw new ApiError(res.status, (body as any)?.detail ?? body);
  return body as T;
}

export async function safe<T>(p: Promise<T>, fallback: T): Promise<{ data: T; error?: string }> {
  try {
    return { data: await p };
  } catch (e) {
    return { data: fallback, error: e instanceof Error ? e.message : String(e) };
  }
}
