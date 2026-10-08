"use client";
import { startTransition, useActionState } from "react";
import { testSso } from "@/app/admin/actions";

import { L, LX } from "@/lib/i18n";
import { useLang } from "@/lib/lang";

export function SsoTester() {
  const lang = useLang();
  const [s, action, pending] = useActionState(async () => testSso(), null);
  return (
    <div className="space-y-2 text-xs" data-testid="sso-test">
      <button className="btn btn-secondary h-8 text-xs" disabled={pending} onClick={() => startTransition(() => action())}>{L(lang, "연결 시험")}</button>
      {s && !s.ok && <p role="alert" className="text-red-600">{LX(lang, s.error)}</p>}
      {s?.ok && (
        <ul className="space-y-1">{s.data.checks.map((c: any) => (
          <li key={c.id} style={{ color: c.ok ? "var(--verdict-allow)" : "var(--verdict-block)" }}>{c.ok ? "✓" : "✗"} {LX(lang, c.title)} — {LX(lang, c.detail)}</li>))}</ul>
      )}
    </div>
  );
}
