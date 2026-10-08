// DPoP 소유 증명 (RFC 9449) — 콘솔 서버가 세션마다 P-256 키를 만들어 API 세션을 그 키에 묶는다 (SCR-B02 · FR-D5-03).
// 개인키는 봉인(AES-256-GCM) 쿠키로만 오가고 브라우저 JS·API 는 볼 수 없다. API 호출마다 htm·htu·iat·jti·ath 를 서명한 새 증명.
import "server-only";
import { createCipheriv, createDecipheriv, createHash, createPrivateKey, generateKeyPairSync, randomBytes, randomUUID, sign, type JsonWebKey } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export const DPOP_COOKIE = "aegis_dpop";
export const MFA_COOKIE = "aegis_mfa";
export const TOTP_COOKIE = "aegis_totp";

// 봉인 키 — WEB_SESSION_SECRET(여러 콘솔 인스턴스가 같은 값). 없으면 .next/cache/aegis-web-secret 에 한 번 만들어 쓴다
// (서버 액션·라우트·화면 번들이 서로 다른 모듈 사본이어도 같은 키 — 단일 인스턴스 전용, 여러 인스턴스면 반드시 설정).
// .next 바로 아래는 dev 서버가 재시작(메모리 임계 자동 재시작 포함)마다 비워 키가 바뀌고 모든 세션이 끊긴다 → cache/ 아래에 둔다.
const SECRET: Buffer = (() => {
  const v = process.env.WEB_SESSION_SECRET;
  if (v && v !== "CHANGE_ME") return createHash("sha256").update(`aegis-web|${v}`).digest();
  const g = globalThis as { __aegisWebSecret?: Buffer };
  if (g.__aegisWebSecret) return g.__aegisWebSecret;
  const f = join(process.cwd(), ".next", "cache", "aegis-web-secret");
  const read = () => { try { const b = readFileSync(f); return b.length === 32 ? b : null; } catch { return null; } };
  let k = read();
  if (!k) {
    k = randomBytes(32);
    try {
      mkdirSync(dirname(f), { recursive: true });
      writeFileSync(f, k, { mode: 0o600, flag: "wx" });
    } catch {
      k = read() ?? k;                                   // 다른 번들이 먼저 만들었다
    }
    console.warn("WEB_SESSION_SECRET 미설정 — .next/cache/aegis-web-secret 로 세션 키를 봉인한다(인스턴스 여러 개면 설정 필요)");
  }
  g.__aegisWebSecret = k;
  return k;
})();

const b64u = (b: Buffer) => b.toString("base64url");

export function seal(v: unknown): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", SECRET, iv);
  const ct = Buffer.concat([c.update(JSON.stringify(v), "utf8"), c.final()]);
  return b64u(Buffer.concat([iv, c.getAuthTag(), ct]));
}

export function unseal<T = any>(s: string | undefined): T | null {
  if (!s) return null;
  try {
    const raw = Buffer.from(s, "base64url");
    const d = createDecipheriv("aes-256-gcm", SECRET, raw.subarray(0, 12));
    d.setAuthTag(raw.subarray(12, 28));
    return JSON.parse(Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString("utf8")) as T;
  } catch {
    return null;
  }
}

export function newKey(): JsonWebKey {
  return generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" });
}

/** htu = API 절대 URL(쿼리 제외). token 이 있으면 ath 를 넣는다. */
export function proof(jwk: JsonWebKey, method: string, url: string, token?: string | null): string {
  const pub = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  const head = b64u(Buffer.from(JSON.stringify({ typ: "dpop+jwt", alg: "ES256", jwk: pub })));
  const htu = url.split("?")[0].split("#")[0];
  const body: Record<string, unknown> = { htm: method.toUpperCase(), htu, iat: Math.floor(Date.now() / 1000), jti: randomUUID() };
  if (token) body.ath = b64u(createHash("sha256").update(token).digest());
  const data = `${head}.${b64u(Buffer.from(JSON.stringify(body)))}`;
  const sig = sign("sha256", Buffer.from(data), { key: createPrivateKey({ key: jwk, format: "jwk" }), dsaEncoding: "ieee-p1363" });
  return `${data}.${b64u(sig)}`;
}
