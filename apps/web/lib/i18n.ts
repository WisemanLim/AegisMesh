// 콘솔 한국어·영어 (NFR-C4). 쿠키 lang 으로 선택, 기본 ko.
import { EN } from "./en";

export type Lang = "ko" | "en";

const DICT = {
  overview: ["개요", "Overview"],
  riskMap: ["위험 지도", "Risk map"],
  catalog: ["카탈로그", "Catalog"],
  instant: ["즉시 사용", "Instant use"],
  findings: ["판정", "Findings"],
  approvals: ["승인 대기함", "Approvals"],
  evidence: ["증적 원장", "Evidence ledger"],
  coverage: ["커버리지", "Coverage"],
  domains: ["위험 영역", "Risk domains"],
  incidents: ["사건", "Incidents"],
  scan: ["상시 점검·격리", "Scans & quarantine"],
  register: ["에이전트 등록", "Register agent"],
  reports: ["통제 보고서", "Control reports"],
  risks: ["위험 등록부", "Risk register"],
  governance: ["거버넌스 점검", "Governance check"],
  redteam: ["레드팀", "Red team"],
  groupDomains: ["위험 영역", "Risk domains"],
  groupOpsRt: ["레드팀·관측", "Red team & ops"],
  groupMain: ["메인", "Main"],
  groupOps: ["판정·사건·승인", "Findings & approvals"],
  groupGov: ["거버넌스·증적", "Governance"],
  approvalsPending: ["승인", "Approvals"],
  groupAdmin: ["설정·관리", "Settings"],
  groupGates: ["관문·정책", "Gates & policies"],
  groupExtended: ["보강 위험(X)", "Extended risks (X)"],
  gates: ["관문 구성·강등", "Gates & degradation"],
  policies: ["정책 목록·버전", "Policies & versions"],
  policyEditor: ["정책 편집기", "Policy editor"],
  simulate: ["판정 시뮬레이터", "Verdict simulator"],
  profileEditor: ["프로파일 편집기", "Profile editor"],
  observability: ["관측·SLO", "Observability & SLO"],
  identity: ["신원·비밀", "Identity & secrets"],
  sso: ["조직 SSO", "Organization SSO"],
  slo: ["SLO·오탐 예산·품질", "SLO · FP budget · quality"],
  sandbox: ["샌드박스·격리 풀", "Sandbox pools"],
  airgap: ["폐쇄망·신뢰 저장소", "Air-gap & trust store"],
  updates: ["업데이트·롤링 교체", "Updates & rolling"],
  instantWizard: ["즉시 사용 마법사", "Instant-use wizard"],
  success: ["성공 지표", "Success metrics"],
  fairness: ["공정성·윤리 지표", "Fairness & ethics"],
  cards: ["시스템·모델 카드", "System & model cards"],
  marketplace: ["장터", "Marketplace"],
  notifications: ["알림", "Notifications"],
  topology: ["배포 토폴로지", "Topology"],
  dataProtection: ["데이터 보호·보존", "Data protection"],
  preview: ["판정 미리보기", "Verdict preview"],
  baseline: ["회귀 기준선·배포 게이트", "Baseline & deploy gate"],
  redteamRun: ["레드팀 실행 승인", "Red team run approval"],
  extended: ["보강 위험(X)", "Extended risks (X)"],
  install: ["설치·첫 실행", "Install & first run"],
  tenants: ["테넌트", "Tenants"],
  users: ["사용자·역할", "Users & roles"],
  account: ["내 계정·세션", "My account"],
  allTenants: ["전체 테넌트", "All tenants"],
  logout: ["로그아웃", "Sign out"],
  appendOnly: ["추가 전용 — 수정·삭제 기능 없음. 만료는 승인된 배치만 (MSG-016)", "Append-only — no edit or delete. Expiry only by approved batch (MSG-016)"],
  readOnly: ["현재 역할로는 읽기 전용입니다 (ST-04)", "Read-only for your role (ST-04)"],
  noData: ["데이터 없음", "No data"],
  verify: ["무결성 검증", "Integrity check"],
  export: ["서명 묶음 내보내기", "Export signed bundle"],
  apply: ["적용", "Apply"],
  release: ["해제", "Release"],
  decide: ["결정", "Decide"],
  approve: ["승인", "Approve"],
  reject: ["거절", "Reject"],
  reason: ["사유(필수)", "Reason (required)"],
} as const;

export type Key = keyof typeof DICT;

export function t(lang: Lang, key: Key): string {
  return DICT[key][lang === "en" ? 1 : 0];
}

/** 화면 본문 한국어·영어 (NFR-C4) — 사전에 없는 화면 문구용 */
export function tr(lang: Lang, ko: string, en: string): string {
  return lang === "en" ? en : ko;
}

export function parseLang(v?: string | null): Lang {
  return v === "en" ? "en" : "ko";
}

/** 본문 번역 — 한국어 원문이 메시지 ID(gettext 방식). en 이면 카탈로그(lib/en.ts)에서 찾고, 없으면 원문 그대로.
 *  앞뒤 공백은 보존하고, 인자는 {0}·{1}… 자리에 넣는다. 서버 액션·API 가 만든 한국어 문장도 같은 함수로 감싸면 카탈로그에 있을 때 번역된다. */
export function L(lang: Lang, ko: string, ...args: unknown[]): string {
  let s = ko;
  if (lang === "en" && HAN.test(ko)) {
    const core = ko.trim();
    const en = translate(core);
    if (en !== undefined) {
      const i = ko.indexOf(core);
      s = ko.slice(0, i) + en + ko.slice(i + core.length);
    }
  }
  return args.length ? s.replace(/\{(\d+)\}/g, (m, i) => (Number(i) < args.length ? String(args[Number(i)] ?? "") : m)) : s;
}

const HAN = /[가-힣]/;

/** API 가 준 값(라벨·메시지·데이터)을 그대로 표시하는 자리 — 문자열이면 번역 시도, 아니면 그대로. */
export function LX<T>(lang: Lang, v: T): T {
  return (typeof v === "string" ? L(lang, v) : v) as T;
}

/** 정확히 일치 → 패턴({n} 와일드카드, 잡힌 값도 번역) → " — "·" · " 로 나눈 조각별 번역(하나라도 번역되면). */
function translate(core: string): string | undefined {
  if (!HAN.test(core)) return undefined;
  const hit = EN[core] ?? matchPattern(core);
  if (hit !== undefined) return hit;
  for (const sep of [" — ", " · ", ", "]) {
    if (!core.includes(sep)) continue;
    const parts = core.split(sep);
    const out = parts.map((x) => translate(x.trim()));
    if (out.some((x) => x !== undefined)) return parts.map((x, i) => out[i] ?? x).join(sep);
  }
  return undefined;
}

/** 서버가 만든 가변 문장(숫자·ID 포함)은 패턴으로 — 카탈로그 키의 {n} 을 와일드카드로 보고, 잡힌 값이 한국어면 그것도 번역한다. */
function matchPattern(core: string): string | undefined {
  for (const [re, en] of PATTERNS) {
    const m = core.match(re);
    if (m) return en.replace(/\{(\d+)\}/g, (_, i) => { const g = m[Number(i) + 1] ?? ""; return g.length < core.length ? translate(g) ?? g : g; });
  }
  return undefined;
}

const PATTERNS: [RegExp, string][] = Object.entries(EN)
  .filter(([k]) => /\{\d+\}/.test(k))
  .sort(([a], [b]) => b.replace(/\{\d+\}/g, "").length - a.replace(/\{\d+\}/g, "").length)   // 고정 글자가 많은(구체적인) 패턴 먼저
  .map(([k, en]) => [new RegExp("^" + k.replace(/[.*+?^$()|[\]\\]/g, "\\$&").replace(/\\?\{(\d+)\\?\}/g, "(.*?)") + "$", "s"), en]);

/** 데이터의 이름 — ko 는 nameKo, en 은 name·nameEn(없으면 id). */
export function nm(lang: Lang, o: { name?: string; nameEn?: string; nameKo?: string; id?: string } | null | undefined): string {
  if (!o) return "";
  return lang === "en" ? o.name ?? o.nameEn ?? o.id ?? o.nameKo ?? "" : o.nameKo ?? o.name ?? o.nameEn ?? o.id ?? "";
}

/** 승인 요약 "{gate} 관문 승인 요청: {규칙}" (서버 저장 문구) — en 에서는 앞부분만 옮긴다. */
export function sumL(lang: Lang, s: string): string {
  return lang === "en" ? s.replace(/^(\w+) 관문 승인 요청: /, "$1 gate approval request: ") : s;
}
