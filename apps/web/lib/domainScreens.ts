// 도메인 상세 화면 목록 (SCR-E02~M04) — 스쿼드 개요(E01·F01…)에서 잇는 링크와 상세 라우트 디스패처가 같이 쓴다.
export type DetailScreen = { view: string; scr: string; ko: string; en: string; items: string[] };

export const DETAIL: Record<string, DetailScreen[]> = {
  D1: [
    { view: "goal-jailbreak", scr: "SCR-E03", ko: "목표 불변식·탈옥 탐지", en: "Goal invariants & jailbreak detection", items: ["D1-02", "D1-03"] },
    { view: "exfil", scr: "SCR-E04", ko: "유출 차단 설정(URL 허용목록·카나리)", en: "Exfiltration controls (URL allowlist · canaries)", items: ["D1-06", "D1-07"] },
  ],
  D2: [
    { view: "pii", scr: "SCR-F02", ko: "민감정보 탐지·로그 마스킹 정책", en: "Sensitive data & log masking", items: ["D2-01", "D2-06"] },
    { view: "isolation", scr: "SCR-F03", ko: "세션 격리·자격증명·무단 접근", en: "Session isolation · credentials · unauthorized access", items: ["D2-02", "D2-03", "D2-04"] },
    { view: "erasure", scr: "SCR-F04", ko: "삭제 전파·학습 데이터 재현 시험", en: "Erasure propagation & training-data recall tests", items: ["D2-05", "D2-07"] },
  ],
  D3: [
    { view: "calls", scr: "SCR-G02", ko: "도구 호출 판정(인자·드라이런)", en: "Tool-call verdicts (args · dry run)", items: ["D3-01", "D3-02"] },
    { view: "sandbox", scr: "SCR-G03", ko: "샌드박스 격리·파일 경로 정책", en: "Sandbox isolation & file-path policy", items: ["D3-03", "D3-04"] },
    { view: "registry", scr: "SCR-G04", ko: "쿼터·권한 상승·도구 레지스트리", en: "Quotas · privilege escalation · tool registry", items: ["D3-05", "D3-06", "D3-07"] },
  ],
  D5: [
    { view: "identity", scr: "SCR-I02", ko: "워크로드 신원·에이전트 카드", en: "Workload identity & agent cards", items: ["D5-01", "D5-04"] },
    { view: "tokens", scr: "SCR-I03", ko: "세션·토큰 감시", en: "Session & token watch", items: ["D5-03", "D5-06"] },
    { view: "authz", scr: "SCR-I04", ko: "인가·위임 체인·권한 드리프트", en: "Authorization · delegation · permission drift", items: ["D5-02", "D5-05", "D5-07"] },
  ],
  D6: [
    { view: "autonomy", scr: "SCR-J02", ko: "자율 레벨·과업 범위·목표 계약", en: "Autonomy level · task scope · goal contract", items: ["D6-01", "D6-04", "D6-05"] },
    { view: "lineage", scr: "SCR-J03", ko: "실행 계보·루프 감지", en: "Execution lineage & loop detection", items: ["D6-02", "D6-03"] },
    { view: "budgets", scr: "SCR-J04", ko: "자원 쿼터·지출 상한", en: "Resource quotas & spend limits", items: ["D6-06", "D6-07"] },
  ],
  D7: [
    { view: "review", scr: "SCR-K02", ko: "서드파티 도구·플러그인 심사", en: "Third-party tool & plugin review", items: ["D7-01", "D7-04"] },
    { view: "sbom", scr: "SCR-K03", ko: "SBOM·의존성·패키지 백도어", en: "SBOM · dependencies · package backdoors", items: ["D7-02", "D7-03"] },
    { view: "integrity", scr: "SCR-K04", ko: "데이터셋·모델·API 공급자 무결성", en: "Dataset · model · API provider integrity", items: ["D7-05", "D7-06", "D7-07"] },
  ],
  D8: [
    { view: "memory", scr: "SCR-L02", ko: "메모리 탐색기·쓰기 승인", en: "Memory explorer & write approval", items: ["D8-02", "D8-03", "D8-06"] },
    { view: "context", scr: "SCR-L03", ko: "컨텍스트·색인 무결성", en: "Context & index integrity", items: ["D8-01", "D8-04", "D8-05"] },
    { view: "bias", scr: "SCR-L04", ko: "검색 편향 지표", en: "Retrieval bias metrics", items: ["D8-07"] },
  ],
  D9: [
    { view: "posture", scr: "SCR-M02", ko: "클라우드·IaC·DB 노출 점검", en: "Cloud · IaC · DB exposure", items: ["D9-01", "D9-04"] },
    { view: "runtime", scr: "SCR-M03", ko: "런타임·엔드포인트 침해 대응", en: "Runtime & endpoint compromise response", items: ["D9-02", "D9-05"] },
    { view: "network", scr: "SCR-M04", ko: "암호화·네트워크·DDoS", en: "Encryption · network · DDoS", items: ["D9-03", "D9-06", "D9-07"] },
  ],
  D4: [
    { view: "grounding", scr: "SCR-H02", ko: "근거성·인용 검증", en: "Groundedness & citation checks", items: ["D4-01", "D4-02"] },
    { view: "decisions", scr: "SCR-H03", ko: "결정 신뢰도 게이트·논리·규정 검사", en: "Decision-confidence gate · logic · compliance", items: ["D4-03", "D4-04", "D4-05"] },
    { view: "propagation", scr: "SCR-H04", ko: "오정보 전파 추적·신뢰 지표", en: "Misinformation propagation & trust metrics", items: ["D4-06", "D4-07"] },
  ],
};

export const INSPECTABLE = new Set(["d1-01", "d1-04", "d1-05"]);   // 입력 검사 뷰어(SCR-E02) 대상 판정
export const TOOL_GATE = new Set(["d3-01", "d3-02", "d3-03", "d3-04", "d3-05", "d3-06", "d3-07", "d4-03"]);   // 도구 호출 상세(SCR-G02)
export const GROUNDING = new Set(["d4-01", "d4-02"]);                // 근거성·인용 검증 뷰어(SCR-H02)

export function findingHref(f: { id: string; traceId: string; agent: { id: string } }): string {
  if (INSPECTABLE.has(f.agent.id)) return `/domains/d1/inspect/${f.id}`;
  if (TOOL_GATE.has(f.agent.id)) return `/domains/d3/calls/${f.traceId}`;
  if (GROUNDING.has(f.agent.id)) return `/domains/d4/grounding/${f.id}`;
  if (f.agent.id === "d6-02" || f.agent.id === "d6-03") return `/domains/d6/lineage/${f.traceId}`;
  if (["d6-01", "d6-04", "d6-05", "d6-06", "d6-07", "d5-05"].includes(f.agent.id)) return `/domains/d3/calls/${f.traceId}`;
  return `/findings/${f.id}`;
}

export function screenOf(d: string, view: string): DetailScreen | undefined {
  return DETAIL[d.toUpperCase()]?.find((x) => x.view === view);
}
