"use client";
// 동적 시크릿 발급 — 원문은 이 응답에서 한 번만 보인다(서버는 해시만 보관).
import { startTransition, useActionState } from "react";
import { issueLease } from "@/app/admin/actions";

import { L, LX } from "@/lib/i18n";
import { useLang } from "@/lib/lang";

export function LeaseIssuer({ tenants }: { tenants: { id: string; name: string }[] }) {
  const lang = useLang();
  const [s, action, pending] = useActionState(issueLease, null);
  return (
    <form onSubmit={(e) => { e.preventDefault(); const fd = new FormData(e.currentTarget); startTransition(() => action(fd)); }} className="space-y-2 text-sm">
      <input name="path" required defaultValue="db/payments-readonly" className="input mono w-full" aria-label="lease path" />
      <input name="scopes" required defaultValue="db:read" placeholder={L(lang, "범위(쉼표) — 호출 단위 최소")} className="input mono w-full" aria-label="scopes" />
      <div className="flex gap-2">
        <input name="ttl" type="number" min={30} defaultValue={300} className="input w-28" aria-label="ttl seconds" />
        {tenants.length > 1 && <select name="tenant" className="input flex-1" aria-label="lease tenant">{tenants.map((t) => <option key={t.id} value={t.id}>{t.id}</option>)}</select>}
        <button className="btn btn-primary" disabled={pending}>{L(lang, "임대 발급")}</button>
      </div>
      {s?.secret && (
        <div className="rounded border border-line bg-primary-soft p-2 text-xs">
          <div className="font-semibold">{L(lang, "지금 복사하세요 — 다시 표시되지 않음 · ")}{LX(lang, s.path)}{L(lang, " · 만료 ")}{new Date(s.expiresAt!).toLocaleTimeString()}</div>
          <code className="mono break-all" data-testid="lease-secret">{LX(lang, s.secret)}</code>
        </div>
      )}
      {s?.error && <p role="alert" className="text-xs text-red-600">{LX(lang, s.error)}</p>}
    </form>
  );
}
