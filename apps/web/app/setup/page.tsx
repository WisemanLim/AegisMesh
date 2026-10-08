// SCR-A06 첫 실행 ① 초기 관리자·테넌트 — 설치 출력(또는 make admin-token)의 1회용 토큰으로 비상 관리자와 첫 테넌트를 만든다.
import Link from "next/link";
import { Banner } from "@/components/Badges";
import { bootstrap } from "@/app/login/actions";
import { SESSION_COOKIE, api, safe } from "@/lib/api";
import { cookies } from "next/headers";

import { L, LX } from "@/lib/i18n";
import { prefs } from "@/lib/session";

export default async function Setup({ searchParams }: { searchParams: Promise<{ err?: string }> }) {
  const { lang } = await prefs();
  const { err } = await searchParams;
  const { data: cfg } = await safe(api("/v1/auth/config", { token: null }), null as any);
  const Wrap = (await cookies()).get(SESSION_COOKIE) ? "div" : "main";     // 로그인 상태면 셸 안 — 셸이 main(랜드마크 하나)
  return (
    <Wrap className="w-full max-w-[640px]">
      <div className="mb-2 text-xs text-muted">{L(lang, "첫 실행 설정 (1/5) · 관리자·SSO → 신원·비밀 → 증적·관측 → 대상·첫 판정 → 검증")}</div>
      <div className="card space-y-4 p-6">
        <h1 className="text-xl font-bold">{L(lang, "초기 관리자 · 첫 테넌트")}</h1>
        {err && <Banner tone="danger">{L(lang, err)}</Banner>}
        {cfg && !cfg.bootstrapRequired && (
          <Banner tone="info">{L(lang, "관리자가 이미 있다. 비상(break-glass) 재설정은 ")}<code className="mono">make admin-token RESET=1</code>{L(lang, " 로 받은 토큰으로만 가능하다. ")}<Link className="text-primary" href="/admin/sso">{L(lang, "② 조직 SSO(OIDC)·그룹→역할 매핑")}</Link> · <Link className="text-primary" href="/setup/identity">{L(lang, "다음 단계 → 신원·비밀")}</Link></Banner>
        )}
        <form action={bootstrap} className="grid grid-cols-2 gap-3 text-sm">
          <label className="col-span-2 block">{L(lang, "① 부트스트랩 토큰 (24시간, 1회용 — 사용 즉시 폐기)")}<input name="token" required placeholder="aegis-boot-…" className="input mono mt-1 w-full" autoComplete="off" />
          </label>
          <label className="block">{L(lang, "비상 관리자 ID")}<input name="username" required pattern="[a-z0-9][a-z0-9._@\-]{2,63}" className="input mt-1 w-full" autoComplete="username" />
          </label>
          <label className="block">{L(lang, "표시 이름")}<input name="displayName" className="input mt-1 w-full" />
          </label>
          <label className="block">{L(lang, "비밀번호 (")}{LX(lang, cfg?.passwordMin ?? 12)}{L(lang, "자 이상)")}<input name="password" type="password" required minLength={cfg?.passwordMin ?? 12} className="input mt-1 w-full" autoComplete="new-password" />
          </label>
          <label className="block">{L(lang, "비밀번호 확인")}<input name="password2" type="password" required className="input mt-1 w-full" autoComplete="new-password" />
          </label>
          <label className="block">{L(lang, "③ 첫 테넌트 ID (소문자·숫자·-)")}<input name="tenantId" defaultValue="default" pattern="[a-z][a-z0-9\-]{1,31}" className="input mono mt-1 w-full" />
          </label>
          <label className="block">{L(lang, "표시 이름")}<input name="tenantName" placeholder={L(lang, "기본 테넌트")} className="input mt-1 w-full" />
          </label>
          <label className="block">{L(lang, "분리 수준")}<select name="isolation" className="input mt-1 w-full" disabled><option>{L(lang, "논리 분리 (정책·증적·인덱스 테넌트 네임스페이스)")}</option></select>
          </label>
          <label className="block">{L(lang, "콘솔 언어")}<select name="lang" className="input mt-1 w-full" defaultValue="ko"><option value="ko">{L(lang, "한국어")}</option><option value="en">English</option></select>
          </label>
          <div className="col-span-2 space-y-2">
            <Banner tone="info">{L(lang, "② 조직 SSO(OIDC)는 /admin/sso 에서 연결한다 — 켜면 로그인 화면에 SSO 버튼이 나오고 비밀번호는 비상 관리자만 쓴다. 이 계정은 평상시 봉인하는 비상 관리자이며 사용 시 원장에 기록된다.")}</Banner>
            <button className="btn btn-primary w-full justify-center">{L(lang, "다음 — 관리자 생성")}</button>
          </div>
        </form>
        <p className="text-xs text-muted">{L(lang, "이미 계정이 있다면 ")}<Link className="text-primary" href="/login">{L(lang, "로그인")}</Link>.</p>
      </div>
    </Wrap>
  );
}
