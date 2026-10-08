// SCR-A04 CLI(aegis) 설치·M1 독립 실행 — 단일 파일 바이너리 빌드·사용, 에이전트별 상세 안내는 /catalog/{id}/run.
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { L, tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";

export default async function Cli() {
  const { lang } = await prefs();
  const blocks: [string, string][] = [
    ["빌드 (단일 파일, 리눅스)", "make cli                       # → dist/aegis-linux-<arch> (PyInstaller onefile, 파이썬 불필요)"],
    ["에이전트·판정", "./aegis list\necho '{\"output\":\"key AKIAIOSFODNN7EXAMPLE\"}' > req.json\n./aegis run d2-03 --input req.json"],
    ["상주 어댑터", "./aegis serve d2-03 --protocol rest --port 8080\n./aegis serve d1-07 --protocol mcp --stdio\n./aegis serve d1-05 --protocol a2a --port 9090 --key card.key --trust-jwks https://aegis.example/v1/identity/jwks   # 서명 AgentCard: /.well-known/agent-card.json"],
    ["A2A 호출 (FR-X01)", "./aegis a2a card http://agent:9090 --trust card-jwks.json            # 카드 서명 검증(대역 밖 신뢰 키)\nAEGIS_SVID=… ./aegis a2a send http://agent:9090 --trust card-jwks.json --token-env AEGIS_SVID --text \"…\""],
    ["품질·검증", "./aegis eval --all              # 골든셋·공격셋·회귀 기준선\n./aegis coverage\n./aegis verify-bundle bundle.json\n./aegis airgap verify b.tar.gz --trust trust.json   # 무네트워크"],
  ];
  return (
    <>
      <PageHeader crumb={tr(lang, "설치 › CLI", "Install › CLI")} title={tr(lang, "CLI (aegis) · M1 독립 실행", "CLI (aegis) · M1 standalone")} />
      <div className="grid grid-cols-2 gap-3">
        {blocks.map(([t, c]) => <section key={t} className="card p-4 text-sm"><h2 className="mb-2 font-semibold">{L(lang, t)}</h2><pre tabIndex={0} className="mono overflow-auto rounded bg-[#f6f7f9] p-3 text-[11px]">{L(lang, c)}</pre></section>)}
      </div>
      <p className="mt-3 text-sm">{tr(lang, "에이전트별 스니펫·AgentCard·지금 시험:", "Per-agent snippets, AgentCard, try it:")} <Link className="text-primary" href="/catalog/d1-05/run">/catalog/d1-05/run</Link></p>
    </>
  );
}
