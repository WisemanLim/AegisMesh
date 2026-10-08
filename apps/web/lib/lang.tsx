"use client";
// 클라이언트 컴포넌트용 언어 — 서버 레이아웃이 쿠키에서 읽은 lang 을 내려준다.
import { createContext, useContext } from "react";
import type { Lang } from "./i18n";

const Ctx = createContext<Lang>("ko");

export function LangProvider({ lang, children }: { lang: Lang; children: React.ReactNode }) {
  return <Ctx.Provider value={lang}>{children}</Ctx.Provider>;
}

export function useLang(): Lang {
  return useContext(Ctx);
}
