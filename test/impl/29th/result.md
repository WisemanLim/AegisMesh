# 시험 결과 / Test Result — impl 29th (Epic 29 D3·D4 상세 화면)
- 일자: 2026-10-06 · 대상: local compose + 헤드리스 Chromium · 커밋: —

## 요약 / Summary
- 전체 10, 통과 10, 실패 0 → 최종 **PASS** (재시도 2회: d4-01 문장 분리가 소수점에서 끊겨 오탐 / 검사기 진단 화면 표시·근거 문서 URL·전파 지점 과다)
- `make test` **352 passed** (+ test_domains_d3d4 5) · `make test-web` 14 + tsc 0 · D3/D4 14종 골든/공격 재생 오탐 0·탐지 1.0
- 측정으로 찾은 결함: **d4-01 문장 분리기가 “1.2%” 의 소수점을 문장 끝으로 봐서 근거 있는 문장을 ‘근거 미확인’ 으로 표시**(오탐) → 소수점 예외 + 골든 표본 추가, d4-01 1.1.0

## 구현
- 엔진(1.1.0): d3-01 드라이런 영향(params.dryRun {tables, rows, reversible} · maxRowsWithoutApproval → dry-run-impact 승인), d3-04 readOnlyPaths(read-only-path 차단), d3-05 quotas + usageToday(quota-exceeded 차단), d3-06 blockedChains + history(blocked-chain 차단)·escalation_paths(정적), d4-03 thresholdsByAction(행동별 임계), d4-04 params.samples 자기일관성(inconsistent 경보), d4-01 소수점 문장 분리. explain: d3-01~07·d4-01~06(판정 불변). 새 표본 run5.jsonl 8건
- 요청 모양에 주체·destination·provenance·zone(문맥 값, 원문 아님)·검색 문서 URL 추가
- 집계·API: `/v1/domains/d3/calls{,/{trace}}`(관문 기록·판정·승인·원장) · `/v1/domains/d3/sandbox`(풀·요구 등급·기동 거부·장악 이벤트) · `/v1/domains/d3/registry`(주체 사용량 대 쿼터·도구 레지스트리(상시 점검 대상·격리·허용목록)·잠재 상승 경로·차단 표시) · `/v1/domains/d4/grounding/{fid}` · `/v1/domains/d4/decisions` · `/v1/domains/d4/propagation`(출처별 지점·정정 상태·신뢰 지표·피드백) · `POST /v1/domains/d4/corrections`(지점 정정·소급 정정, 원장 correction)
- 콘솔: `/domains/d3/{calls,sandbox,registry}`, `/domains/d3/calls/[trace]`(인자·사전조건/드라이런/명령 주입/근거·원장 + 승인 카드에서 바로 결정), `/domains/d4/{grounding,decisions,propagation}`, `/domains/d4/grounding/[fid]`. 검사기 진단 렌더러 13종 추가. 승인 결정 액션에 같은 사이트 경로로만 돌아가는 back(//host·/\host 거부)

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T29-01 | PASS | require_approval D3-01.dry-run-impact ratio 12.41 · 3행 allow · 임계 20,000 이어도 되돌림 불가 → 승인 |
| T29-02 | PASS | shell-meta 차단(셸 문맥·메타문자), ../../etc/shadow → /etc/shadow 이탈·민감 → block, /repo 쓰기 read-only-path |
| T29-03 | PASS | quota-exceeded(오늘 10 ≥ 10), blocked-chain(files.read → secrets.list), 유효 범위 [repo:read] · 부족 [repo:write] → 차단 |
| T29-04 | PASS | 목록: db.execute · kang(dev-copilot), 상세: 인자 [db, sql]·d3-01/d3-02·승인 pending·원장 seq, 응답에 SQL 원문 없음 |
| T29-05 | PASS | kang 오늘 2/2 → over, files.read→secrets.list blocked ✓, 풀 L0·L1 사용 가능 / L2·L3 런타임 없음 |
| T29-06 | PASS | 문장 [✓, ✗](소수점 수정 후), DOI 제거·URL 유지, payment 0.86 < 0.9 → 승인(기본 0.75 에선 통과), 12,400 ≠ 12,000·일치율 0, 원금 보장 → finance-guarantee 차단 |
| T29-07 | PASS | 근거 문서 kb/fee-policy-2026.pdf·URL, 인용 형제(D4-02), deploy 0.5 → 승인 대기, 출처 fnd_src → index·memory(게이트 차단), 정정 기록·소급 정정(완료·차단 제외) |
| T29-08 | PASS | logs/e2e.txt·e2e-r2.txt · g02·g03·g04·h02·h03·h04-ko.png — 승인 카드 appr.one 1/2 → appr.two 2/2 approved(같은 화면으로 복귀), 정정 기록 원장 #66732, 콘솔 오류 0 |
| T29-09 | PASS | logs/en-sweep.txt·en-sweep-r2.txt — 개요·목록·결정 화면 한글 0~7(판정 메모), 남은 한글 = 판정 근거·규칙 설명·승인 사유·마커 문자열 · ko 7 경로 오류 0 |
| T29-10 | PASS | 352 passed · vitest 14 · tsc 0 |

## 회차 / Rounds
- round 1: test_d4_engines_explain — 문장 [✗, ✓, ✗] (소수점 분리) → 엔진 수정, 골든 표본 추가
- round 2: E2E — 검사기 진단이 JSON 으로만 보임(새 kind) → 렌더러 13종, 근거 문서 URL 없음 → 요청 모양에 url, 전파 화면 36k 자(출처 미표기 지점 수백) → 출처당 최근 20 + 전체 수, d4-02 판정 자체를 열면 인용 비어 보임 → 자기 자신 사용

## 남은 것 / Notes
- E2E 중 garam 정책에 도구 허용목록을 넣으려다 **정책 단위 시험(“문서 검색 통과”·“고위험 이체”)에 막혔다** — 시험에 쓰이는 도구를 넣자 배포됨(v14). 허용목록이 기존 흐름을 깨는 것을 배포 전에 막는 설계대로 동작. 시험 뒤 원복(v16·v17).
- 레이트·쿼터 집행은 게이트웨이가 집계 값을 실어 보낼 때 — 플랫폼은 관문 기록으로 관측·대조만. 비용 단위 과금 연동(Kong·Envoy·APISIX)은 없다.
