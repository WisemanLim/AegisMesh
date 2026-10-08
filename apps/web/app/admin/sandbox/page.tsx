// SCR-R04 샌드박스·격리 풀 — 등급별 용량·사용·대기·거부·회수, 커널 잠금 수단, 탈출 점검.
import { Banner, Chip } from "@/components/Badges";
import { PageHeader } from "@/components/Shell";
import { api, safe } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { t, tr, LX } from "@/lib/i18n";
import { can, me, prefs } from "@/lib/session";
import { runSandboxProbe } from "../actions";

import { L } from "@/lib/i18n";

export default async function Sandbox({ searchParams }: { searchParams: Promise<{ msg?: string }> }) {
  const { lang } = await prefs();
  const user = await me();
  const { msg } = await searchParams;
  const [{ data: st, error }, probes] = await Promise.all([
    safe(api("/v1/sandbox"), null as any),
    safe(api("/v1/evidence?kind=sandbox&limit=5"), { items: [] as any[] }),
  ]);
  if (!st) return <><PageHeader crumb={t(lang, "groupAdmin")} title={tr(lang, "샌드박스", "Sandbox")} /><Banner tone="danger">{error}</Banner></>;
  const caps = st.capabilities;
  return (
    <>
      <PageHeader crumb={`${t(lang, "groupAdmin")} › ${t(lang, "sandbox")}`} title={tr(lang, `샌드박스 · 격리 풀 (최고 등급 ${st.maxLevel})`, `Sandbox · isolation pools (max ${st.maxLevel})`)} />
      {msg && <div className="mb-3"><Banner tone={msg.includes(L(lang, "실패")) ? "danger" : "info"}>{L(lang, msg)}</Banner></div>}
      <div className="card mb-4 overflow-hidden" data-testid="pools">
        <table className="grid-table text-sm">
          <thead><tr><th>{L(lang, "등급")}</th><th>{L(lang, "수단")}</th><th>{L(lang, "상태")}</th><th>{L(lang, "슬롯")}</th><th>{L(lang, "사용 중")}</th><th>{L(lang, "대기")}</th><th>{L(lang, "처리")}</th><th>{L(lang, "거부")}</th><th>{L(lang, "시간 초과")}</th><th>{L(lang, "오류")}</th><th>{L(lang, "발급")}</th><th>{L(lang, "회수")}</th></tr></thead>
          <tbody>{st.pools.map((p: any) => (
            <tr key={p.level}>
              <td><b>{LX(lang, p.level)}</b></td><td className="text-xs">{LX(lang, p.mechanism)}</td>
              <td>{p.available ? <Chip tone="primary">{L(lang, "사용 가능")}</Chip> : <span className="text-xs" style={{ color: "var(--verdict-block)" }}>{LX(lang, p.status)}</span>}</td>
              <td>{LX(lang, p.capacity ?? "∞")}</td><td>{LX(lang, p.active)}</td><td>{LX(lang, p.queued)}</td><td>{LX(lang, p.served)}</td><td>{LX(lang, p.rejected)}</td><td>{LX(lang, p.timeouts)}</td><td>{LX(lang, p.errors)}</td><td>{LX(lang, p.spawned)}</td><td>{LX(lang, p.recycled)}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
      <div className="grid grid-cols-3 gap-4">
        <section className="card p-4 text-sm" data-testid="caps">
          <h2 className="mb-2 font-semibold">{L(lang, "커널 잠금 수단 (실측)")}</h2>
          <ul className="space-y-1 text-xs">
            <li>Landlock {caps.landlock ? <Chip tone="primary">ABI {LX(lang, caps.landlock)}</Chip> : <Chip>{L(lang, "없음 — 감사 훅만")}</Chip>}{L(lang, " — 읽기: 런타임·에이전트 디렉터리 / 쓰기: 임시 디렉터리")}</li>
            <li>seccomp-BPF {caps.seccomp?.length ? <Chip tone="primary">{caps.seccomp.length}{L(lang, "개 차단")}</Chip> : <Chip>{L(lang, "없음")}</Chip>} <span className="mono">{(caps.seccomp ?? []).join(" · ")}</span></li>
            <li>rlimit CPU {LX(lang, caps.rlimits?.cpuSec)}{L(lang, "s · 메모리 ")}{LX(lang, caps.rlimits?.memoryMB)}{L(lang, "MB · 파일 ")}{LX(lang, caps.rlimits?.nofile)}{L(lang, " · 쓰기 ")}{LX(lang, caps.rlimits?.fsizeMB)}MB</li>
            <li>{L(lang, "감사 훅 · 빈 환경(DB·키·토큰 미전달) · 일회용 임시 FS")}</li>
            <li className="text-muted">{LX(lang, caps.machine)}{L(lang, " · 커널 ")}{LX(lang, caps.kernel)}</li>
          </ul>
          <p className="mt-2 text-xs text-muted">{LX(lang, st.policy)}{L(lang, " · 웜 하위 프로세스 ")}{LX(lang, st.recycleUses)}{L(lang, "회 사용 후 회수 · 대기 ")}{LX(lang, st.queueSec)}s</p>
        </section>
        <section className="card p-4 text-sm">
          <h2 className="mb-2 font-semibold">{L(lang, "L1 웜 슬롯 (")}{st.workers.length})</h2>
          <table className="grid-table text-xs"><thead><tr><th>{L(lang, "에이전트")}</th><th>pid</th><th>{L(lang, "사용")}</th><th>{L(lang, "시작")}</th></tr></thead>
            <tbody>{st.workers.length === 0 ? <tr><td colSpan={4} className="text-muted">{L(lang, "없음 (L1 요구 에이전트가 판정할 때 발급)")}</td></tr> :
              st.workers.map((w: any) => <tr key={w.pid}><td>{LX(lang, w.agent)}</td><td>{LX(lang, w.pid)}</td><td>{LX(lang, w.uses)}</td><td>{fmtTime(new Date(w.startedAt * 1000).toISOString())}</td></tr>)}</tbody></table>
          <p className="mt-2 text-xs text-muted">{L(lang, "하위 프로세스는 판정(Decision)만 돌려주고 Finding 은 부모가 매니페스트로 검증해 만든다.")}</p>
        </section>
        <section className="card p-4 text-sm" data-testid="probe">
          <div className="mb-2 flex items-center justify-between"><h2 className="font-semibold">{L(lang, "탈출 점검")}</h2>
            {can(user, "sandbox") && <form action={runSandboxProbe}><button className="btn btn-primary h-8 text-xs">{L(lang, "지금 점검")}</button></form>}</div>
          <ul className="space-y-1 text-xs">{probes.data.items.map((e: any) => (
            <li key={e.seq}>{fmtTime(e.createdAt)} · {LX(lang, e.body.by)} · {LX(lang, e.body.blocked)}/{e.body.total}{L(lang, " 차단 ")}{e.body.ok ? "✓" : "✗"}</li>
          ))}</ul>
          <p className="mt-2 text-xs text-muted">{L(lang, "네트워크 연결·libc 소켓 직접 호출·프로세스 실행·fork·/app/data 쓰기·원장 키 읽기·/etc 쓰기·메모리 2GB·환경 비밀")}</p>
        </section>
      </div>
    </>
  );
}
