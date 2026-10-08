"use client";
// 패스키·보안 키(WebAuthn) 버튼 — 서버가 준 옵션(base64url)을 브라우저 API 형식으로 바꿔 인증기를 부르고, 결과를 JSON 으로 서버 액션에 넘긴다.
// 비밀(개인키)은 인증기 밖으로 나오지 않는다. 등록(create)·인증(get) 공용 (SCR-B02 ②).
import { useState, useTransition } from "react";

type R = { ok: boolean; error?: string; msg?: string } | null | void;
const b2u = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0)).buffer;
const u2b = (b: ArrayBuffer | null) => (b ? btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") : null);

function prepare(pk: any, mode: "get" | "create") {
  const o = { ...pk, challenge: b2u(pk.challenge) };
  if (mode === "create") {
    o.user = { ...pk.user, id: b2u(pk.user.id) };
    o.excludeCredentials = (pk.excludeCredentials ?? []).map((c: any) => ({ ...c, id: b2u(c.id) }));
  } else {
    o.allowCredentials = (pk.allowCredentials ?? []).map((c: any) => ({ ...c, id: b2u(c.id) }));
  }
  return o;
}

function serialize(c: PublicKeyCredential) {
  const r: any = c.response;
  const response = r.attestationObject
    ? { clientDataJSON: u2b(r.clientDataJSON), attestationObject: u2b(r.attestationObject), transports: r.getTransports?.() ?? [] }
    : { clientDataJSON: u2b(r.clientDataJSON), authenticatorData: u2b(r.authenticatorData), signature: u2b(r.signature), userHandle: u2b(r.userHandle) };
  return { id: c.id, rawId: u2b(c.rawId), type: c.type, response };
}

export function PasskeyButton({ mode, publicKey, action, fields = {}, label, busyLabel, className, testId, needName, namePlaceholder }: {
  mode: "get" | "create"; publicKey: any; action: (form: FormData) => Promise<R>; fields?: Record<string, string>; label: string; busyLabel: string;
  className?: string; testId?: string; needName?: boolean; namePlaceholder?: string;
}) {
  const [busy, start] = useTransition();
  const [err, setErr] = useState<string>();
  const [name, setName] = useState("");
  const run = () => start(async () => {
    setErr(undefined);
    if (!window.PublicKeyCredential) return setErr("WebAuthn unsupported (secure context: https or localhost)");
    try {
      const opt = prepare(publicKey, mode);
      const cred = (mode === "create" ? await navigator.credentials.create({ publicKey: opt }) : await navigator.credentials.get({ publicKey: opt })) as PublicKeyCredential | null;
      if (!cred) return setErr("cancelled");
      const f = new FormData();
      Object.entries(fields).forEach(([k, v]) => f.set(k, v));
      f.set("credential", JSON.stringify(serialize(cred)));
      if (needName) f.set("name", name || "passkey");
      const r = await action(f);
      if (r && !r.ok) setErr(r.error);
    } catch (e) {
      setErr((e as Error).message);
    }
  });
  return (
    <div className="space-y-1">
      <div className="flex gap-2">
        {needName && <input value={name} onChange={(e) => setName(e.target.value)} placeholder={namePlaceholder} className="input h-8 flex-1 text-xs" aria-label="passkey name" />}
        <button type="button" onClick={run} disabled={busy} className={className ?? "btn btn-primary w-full justify-center"} data-testid={testId}>{busy ? busyLabel : label}</button>
      </div>
      {err && <p role="alert" className="text-xs text-red-600" data-testid={testId ? `${testId}-error` : undefined}>{err}</p>}
    </div>
  );
}
