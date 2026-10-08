"use client";
// 확인 대화상자 버튼 (MSG-018 적용 · MSG-019 해제) — 취소하면 폼을 보내지 않는다.
export function ConfirmButton({ message, className, children, disabled, title }: { message: string; className?: string; children: React.ReactNode; disabled?: boolean; title?: string }) {
  return (
    <button className={className} disabled={disabled} title={title} onClick={(e) => { if (!window.confirm(message)) e.preventDefault(); }}>
      {children}
    </button>
  );
}
