"use client";
// API 토큰 발급 — 원문은 이 응답에서 한 번만 보인다(서버에는 id 만 남음).
import { useActionState } from "react";
import { issueToken } from "@/app/admin/actions";

import { L, LX } from "@/lib/i18n";
import { useLang } from "@/lib/lang";

export function TokenIssuer({ userId }: { userId: string }) {
  const lang = useLang();
  const [state, action, pending] = useActionState(issueToken, null);
  return (
    <form action={action} className="flex flex-wrap items-center gap-1 text-xs">
      <input type="hidden" name="id" value={userId} />
      <input name="name" required placeholder={L(lang, "토큰 이름")} className="input h-7 w-28 text-xs" aria-label="token name" />
      <input name="ttl" type="number" min={1} placeholder={L(lang, "일(선택)")} className="input h-7 w-20 text-xs" aria-label="ttl days" />
      <button className="btn btn-secondary h-7 text-xs" disabled={pending}>{L(lang, "토큰 발급")}</button>
      {state?.token && (
        <div className="mt-1 w-full rounded border border-line bg-primary-soft p-2">
          <div className="font-semibold">{L(lang, "지금 복사하세요 — 다시 표시되지 않음")}</div>
          <code className="mono break-all" data-testid="issued-token">{LX(lang, state.token)}</code>
        </div>
      )}
      {state?.error && <div role="alert" className="mt-1 w-full text-red-600">{LX(lang, state.error)}</div>}
    </form>
  );
}
