"use client";
import { startTransition, useActionState, useState } from "react";
import { maskTest } from "@/app/observability/actions";

import { L, LX } from "@/lib/i18n";
import { useLang } from "@/lib/lang";

export function MaskTester({ canSend }: { canSend: boolean }) {
  const lang = useLang();
  const [text, setText] = useState("문의 kim.hana@garam.example · 010-1234-5678 · 카드 4111-1111-1111-1111 · 900101-1234567");
  const [s, action, pending] = useActionState(maskTest, null);
  const run = (send: boolean) => {
    const fd = new FormData();
    fd.set("text", text);
    if (send) fd.set("send", "1");
    startTransition(() => action(fd));
  };
  const d = s?.ok ? s.data : null;
  return (
    <div className="space-y-2 text-sm">
      <textarea value={text} onChange={(e) => setText(e.target.value)} className="input mono h-20 w-full text-xs" aria-label="test log" />
      <div className="flex gap-2">
        <button type="button" onClick={() => run(false)} className="btn btn-secondary" disabled={pending}>{L(lang, "미리보기")}</button>
        <button type="button" onClick={() => run(true)} className="btn btn-primary" disabled={pending || !canSend} title={canSend ? "" : L(lang, "거버넌스 권한 필요")}>{L(lang, "시험 로그 전송")}</button>
      </div>
      {s && !s.ok && <p role="alert" className="text-red-600">{LX(lang, s.error)}</p>}
      {d && (
        <div className="card p-3" data-testid="mask-result">
          <div className="mono text-xs">{LX(lang, d.masked ?? d.preview)}</div>
          <p className="mt-1 text-xs text-muted">{L(lang, "적용 규칙 ")}{(d.rules ?? []).join(", ") || L(lang, "없음")}{d.sent ? (d.sent && d.traceId ? L(lang, " · 전송됨 trace {0} — 수집기 출력에서 치환 확인", d.traceId) : L(lang, " · 미전송: {0}", d.reason)) : L(lang, " · 미리보기(저장·전송 없음)")}</p>
        </div>
      )}
    </div>
  );
}
