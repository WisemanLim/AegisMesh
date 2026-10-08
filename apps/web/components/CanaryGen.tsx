"use client";
// 카나리 토큰 생성 — 브라우저 안 난수(crypto.getRandomValues). 시스템 지시에 심고 아래 카나리 목록에 등록한다.
import { useState } from "react";
import { tr } from "@/lib/i18n";
import { useLang } from "@/lib/lang";

const ABC = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export function CanaryGen() {
  const lang = useLang();
  const [tok, setTok] = useState("");
  const gen = () => {
    const b = new Uint8Array(12);
    crypto.getRandomValues(b);
    setTok(`AEGIS-CANARY-${[...b].map((x) => ABC[x % ABC.length]).join("")}`);
  };
  return (
    <div className="flex items-center gap-2 text-xs" data-testid="canary-gen">
      <button type="button" className="btn btn-secondary h-7 text-xs" onClick={gen}>{tr(lang, "새 카나리 생성", "Generate canary")}</button>
      {tok && <code className="mono rounded bg-[#f6f7f9] px-2 py-1" data-testid="canary-token">{tok}</code>}
      {tok && <span className="text-muted">{tr(lang, "→ 시스템 지시에 심고 아래 canaries 에 추가 후 시험·배포", "→ plant it in the system prompt, add to canaries below, then test & deploy")}</span>}
    </div>
  );
}
