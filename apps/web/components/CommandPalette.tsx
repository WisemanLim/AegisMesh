"use client";
// SCR-B05 전역 검색·명령 팔레트 — ⌘K/Ctrl+K. 에이전트·항목·판정 ID·traceId·사건·정책·화면 검색, '>' 로 명령.
// 권한 없는 명령은 비활성 + 사유. 실행은 해당 화면으로 이동(파괴적 작업은 화면의 확인·승인 절차를 그대로 거친다).
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { L } from "@/lib/i18n";
import { useLang } from "@/lib/lang";

type Hit = { id: string; label: string; href: string };
const GROUPS: [string, string][] = [["agents", "에이전트"], ["items", "도식 항목"], ["findings", "판정"], ["incidents", "사건"], ["policies", "정책"], ["screens", "화면"]];
const COMMANDS = [
  { label: "> 정책 배포 (편집기)", href: "/policies/edit", perm: "policy.write" },
  { label: "> 판정 시뮬레이션", href: "/simulate", perm: "read" },
  { label: "> 증적 묶음 내보내기", href: "/evidence/export", perm: "evidence.export" },
  { label: "> 레드팀 실행 요청", href: "/redteam/run", perm: "redteam" },
  { label: "> 거버넌스 자체 점검", href: "/governance", perm: "governance" },
  { label: "> 샌드박스 탈출 점검", href: "/admin/sandbox", perm: "sandbox" },
  { label: "> 신원 즉시 전체 회전", href: "/admin/identity", perm: "identity" },
  { label: "> 폐쇄망 번들 반입", href: "/admin/airgap", perm: "tenant.admin" },
  { label: "> 판정 미리보기(재생)", href: "/instant/preview", perm: "read" },
];

export function CommandPalette({ perms }: { perms: string[] }) {
  const lang = useLang();
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [hits, setHits] = useState<Record<string, Hit[]>>({});
  const [sel, setSel] = useState(0);
  const router = useRouter();
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setOpen((o) => !o); }
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  useEffect(() => { if (open) { setTimeout(() => input.current?.focus(), 0); } else { setQ(""); setHits({}); } }, [open]);
  useEffect(() => {
    if (q.startsWith(">") || q.trim().length < 2) { setHits({}); return; }
    const ctl = new AbortController();
    const id = setTimeout(() => fetch(`/search?q=${encodeURIComponent(q)}`, { signal: ctl.signal }).then((r) => r.json()).then(setHits).catch(() => {}), 150);
    return () => { clearTimeout(id); ctl.abort(); };
  }, [q]);

  const cmds = COMMANDS.filter((c) => q.startsWith(">") ? c.label.includes(q.slice(1).trim()) : false);
  const flat: { label: string; href: string; group: string; disabled?: string }[] = q.startsWith(">")
    ? cmds.map((c) => ({ label: c.label, href: c.href, group: "명령", disabled: perms.includes(c.perm) ? undefined : L(lang, "권한 없음: {0}", c.perm) }))
    : GROUPS.flatMap(([k, g]) => (hits[k] ?? []).map((h) => ({ label: h.label, href: h.href, group: g })));
  const go = (i: number) => { const h = flat[i]; if (h && !h.disabled) { setOpen(false); router.push(h.href); } };

  return (
    <>
      <button onClick={() => setOpen(true)} className="flex h-7 items-center gap-2 rounded-md border border-line px-2 text-xs text-muted" aria-label="search">{L(lang, "⌘K 에이전트·판정·trace 검색")}</button>
      {open && (
        <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/30 pt-24" onClick={() => setOpen(false)}>
          <div className="w-[640px] rounded-lg border border-line bg-panel shadow-xl" onClick={(e) => e.stopPropagation()} role="dialog" aria-label="command palette">
            <input ref={input} value={q} onChange={(e) => { setQ(e.target.value); setSel(0); }} data-testid="palette-input"
              onKeyDown={(e) => { if (e.key === "ArrowDown") setSel((s) => Math.min(s + 1, flat.length - 1)); if (e.key === "ArrowUp") setSel((s) => Math.max(s - 1, 0)); if (e.key === "Enter") go(sel); }}
              placeholder={L(lang, "에이전트 ID·이름, 판정 ID, traceId, 사건, 정책, 화면 — '>' 로 명령")} className="w-full border-b border-line bg-transparent px-4 py-3 text-sm outline-none" />
            <ul className="max-h-96 overflow-auto py-1 text-sm" data-testid="palette-results">
              {flat.length === 0 && <li className="px-4 py-3 text-xs text-muted">{q.length < 2 ? L(lang, "두 글자 이상 입력 · '>' 명령 목록") : L(lang, "결과 없음")}</li>}
              {flat.map((h, i) => (
                <li key={h.group + h.href + h.label}>
                  <button onClick={() => go(i)} disabled={!!h.disabled} title={h.disabled}
                    className={`flex w-full justify-between px-4 py-1.5 text-left ${i === sel ? "bg-primary-soft" : ""} ${h.disabled ? "opacity-50" : ""}`}>
                    <span>{L(lang, h.label)}</span><span className="text-xs text-muted">{L(lang, h.disabled ?? h.group)}</span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </>
  );
}
