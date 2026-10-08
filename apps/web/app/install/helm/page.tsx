// SCR-A02 쿠버네티스 헬름 설치 마법사 — 값 입력 → values.yaml·설치 명령 생성 (비밀값은 existingSecret 권장).
import { PageHeader } from "@/components/Shell";
import { tr } from "@/lib/i18n";
import { prefs } from "@/lib/session";

import { L } from "@/lib/i18n";

type SP = { release?: string; ns?: string; secret?: string; replicas?: string; storage?: string; host?: string; collector?: string; db?: string };

export default async function Helm({ searchParams }: { searchParams: Promise<SP> }) {
  const { lang } = await prefs();
  const sp = await searchParams;
  const v = { release: sp.release || "aegis", ns: sp.ns || "aegismesh", secret: sp.secret || "aegismesh-secrets", replicas: sp.replicas || "1",
    storage: sp.storage || "", host: sp.host || "", collector: sp.collector !== "off", db: sp.db || "bundled" };
  const multi = Number(v.replicas) > 1;
  const values = `secrets:
  existingSecret: ${v.secret}       # ${lang === "en" ? "keys" : "키"}: DB_PASSWORD · LEDGER_SIGNING_KEY · SVID_SIGNING_KEY · AUTH_SECRET
api:
  replicas: ${v.replicas}
persistence:
  accessMode: ${multi ? "ReadWriteMany   # api.replicas > 1" : "ReadWriteOnce"}${v.storage ? `\n  storageClass: ${v.storage}` : ""}
postgresql:
  enabled: ${v.db === "bundled"}${v.db === "external" ? "\nexternalDatabase:\n  url: postgresql+psycopg://app:<" + L(lang, "비밀") + ">@<host>:5432/app" : ""}
collector:
  enabled: ${v.collector}
ingress:
  enabled: ${!!v.host}${v.host ? `\n  host: ${v.host}` : ""}`;
  const secretCmd = `kubectl -n ${v.ns} create secret generic ${v.secret} \\
  --from-literal=DB_PASSWORD="$(openssl rand -hex 16)" \\
  --from-literal=LEDGER_SIGNING_KEY="$(openssl rand -base64 32)" \\
  --from-literal=SVID_SIGNING_KEY="$(openssl rand -base64 32)" \\
  --from-literal=AUTH_SECRET="$(openssl rand -base64 32)"`;
  return (
    <>
      <PageHeader crumb={tr(lang, "설치 › 쿠버네티스", "Install › Kubernetes")} title={tr(lang, "헬름 설치 마법사", "Helm install wizard")} />
      <div className="grid grid-cols-[320px_1fr] gap-4">
        <form method="get" className="card space-y-2 p-4 text-sm">
          {([["release", "릴리스 이름"], ["ns", "네임스페이스"], ["secret", "existingSecret 이름"], ["replicas", "api 복제 수"], ["storage", "스토리지 클래스(선택)"], ["host", "인그레스 호스트(선택)"]] as const).map(([k, l]) => (
            <label key={k} className="block">{L(lang, l)}<input name={k} defaultValue={(v as any)[k]} className="input mt-1 w-full" /></label>
          ))}
          <label className="block">DB<select name="db" defaultValue={v.db} className="input mt-1 w-full"><option value="bundled">{L(lang, "번들 PostgreSQL (StatefulSet)")}</option><option value="external">{L(lang, "외부 PostgreSQL")}</option></select></label>
          <label className="block">{L(lang, "관측 수집기")}<select name="collector" defaultValue={v.collector ? "on" : "off"} className="input mt-1 w-full"><option value="on">{L(lang, "포함")}</option><option value="off">{L(lang, "제외")}</option></select></label>
          <button className="btn btn-primary w-full justify-center">{L(lang, "값 생성")}</button>
        </form>
        <div className="space-y-3 text-sm">
          <section className="card p-4"><h2 className="mb-2 font-semibold">{L(lang, "① 비밀 (KMS·external-secrets 권장 — 예시는 로컬 생성)")}</h2><pre tabIndex={0} className="mono overflow-auto rounded bg-[#f6f7f9] p-3 text-[11px]">{secretCmd}</pre></section>
          <section className="card p-4"><h2 className="mb-2 font-semibold">② values.yaml</h2><pre tabIndex={0} className="mono overflow-auto rounded bg-[#f6f7f9] p-3 text-[11px]" data-testid="helm-values">{values}</pre></section>
          <section className="card p-4"><h2 className="mb-2 font-semibold">{L(lang, "③ 설치 · 첫 실행")}</h2><pre tabIndex={0} className="mono overflow-auto rounded bg-[#f6f7f9] p-3 text-[11px]">{`helm upgrade --install ${v.release} deploy/helm/aegismesh -n ${v.ns} --create-namespace -f values.yaml --wait --wait-for-jobs
kubectl -n ${v.ns} exec deploy/${v.release}-api -- python -m app.admin bootstrap-token
kubectl -n ${v.ns} port-forward svc/${v.release}-web 3000:3000   # → /setup`}</pre>
            <p className="mt-2 text-xs text-muted">{L(lang, "마이그레이션·시드는 post-install 훅 Job 이 수행. 폐쇄망은 이미지를 내부 레지스트리에 미러하고 image.*.repository 를 바꾼다. 리허설: ")}<code className="mono">make k8s-rehearsal</code>{L(lang, " (로컬 k3d).")}</p></section>
        </div>
      </div>
    </>
  );
}
