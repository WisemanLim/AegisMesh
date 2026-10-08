# 시험 결과 / Test Result — impl 31st (Epic 31 D7·D8·D9 상세 화면)
- 일자: 2026-10-06 · 대상: local compose + 헤드리스 Chromium · 커밋: —

## 요약 / Summary
- 전체 7, 통과 7, 실패 0 → 최종 **PASS** (재시도 3회: 견본 파서 꼬리 쉼표 / 런타임 침해 호스트 격리 없음 → 자동 격리 / 견본·엔진 불일치 2건)
- `make test` **361 passed** (+ test_domains_d7d9 4) · `make test-web` 14 + tsc 0 · d7-02·d9-04·d9-06 골든/공격 재생 오탐 0·탐지 1.0
- 측정으로 찾은 결함: **d9-04 가 DDL 권한을 과대 권한으로 보지 않음**(에이전트 DDL·DML 직접 계정 통과) → DDL 추가 · **d9-06 이 메시 mTLS 밖 내부 평문 흐름을 못 봄** → 흐름별 `mtls: false` 면 차단(메시 안 평문 = 통과라는 기존 골든은 유지) · **상시 점검이 침해 호스트를 격리하지 않음** → runtime_events 차단 시 host 격리

## 구현
- 공통 보드 `/v1/domains/artifacts/{review|sbom|integrity|index|posture|runtime|network}`(대상·최근 점검 근거·격리·대기 승인·결정) + `POST /v1/domains/decisions`(approve·conditional·reject·retest·accept-change·restore·allow·pin-update·release, 2인 = 승인함) · 승인 행동 `supply_decision`(원장 supply)·`quarantine_release`(격리 해제)
- D8: `/v1/domains/d8/memory`(판정 기록의 메모리 메타·쓰기 요청 승인·재스캔), `/v1/domains/d8/context?trace=`(구획 T0 시스템·T1 사용자·T2 신뢰 문서/메모리·T3 외부, 구획별 근거), `/v1/domains/d8/bias?days=`(출처 분포·정규화 엔트로피·상위 점유 대 한도·추세·레드팀 공정성 그룹·가중치 제안)
- CLI `aegis sbom check <CycloneDX|SPDX JSON> [--advisories] [--fail-on]` — purl → 생태계, d7-02 로 판정, exit 1/0
- 엔진(1.1.0): d7-02 수정 버전 근거, d9-04 DDL, d9-06 plaintext-internal(흐름별 mtls false). 스캐너: runtime_events 차단 → host 격리
- 콘솔: `/domains/d7/{review,sbom,integrity}` · `/domains/d8/{memory,context,bias}` · `/domains/d9/{posture,runtime,network}`, `components/ScanPanel`(견본 → 지금 점검·주기 등록), `lib/artifactPresets.ts` 18종, 공통 `ArtifactBoard`(지금 점검·결정)

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T31-01 | PASS | pytest: 차단·근거 메모, 반려 seq, 승인 → approve-sensitive 2인 → 승인 후 결정 반영, 재시험 block · 화면: 점검 패널 plugin → block·격리·사건, mcp-jira-server 승인 → 2인 요청, skill 반려 원장 #69809 |
| T31-02 | PASS | host dev-copilot-7f9 자동 격리 → release 2인 승인 → 격리 해제 (pytest) · 화면: 등록·지금 점검 block·“격리 중 호스트 dev-copilot-7f9”·해제 요청 |
| T31-03 | PASS | CycloneDX critical → 1, 권고 없음 → 0, SPDX critical fail-on critical → 1 · 컨테이너에서 출력 “✗ 3 components · 2 vulnerable · worst critical → exit 1” |
| T31-04 | PASS | user.pref.limit(loan-review-agent·미승인), 구획 text T1·segments[0] T3·retrieval:kb#1182 T3·memory, blog-a 분포·다양성 |
| T31-05 | PASS | logs/e2e.txt·e2e-r2.txt · k02~m04-ko.png — K03 구성요소 3·critical 1·high 1·빌드 차단·백도어 1, K04 3열(해시 ✗·posix.system·핀 ✗), M04 mTLS 50%·인증서 3일 적색·흐름 mTLS ✗, 콘솔 오류 0 |
| T31-06 | PASS | d9-04 copilot_rw(DDL) → block, d9-06 d8-05→10.0.3.9 mtls false → block, internal-plain-unknown(메시 mTLS) 통과 유지 |
| T31-07 | PASS | en 12 경로 화면 문구 한글 0(남은 것 = 판정 근거·승인 사유), 361 passed · vitest 14 · tsc 0 |

## 회차 / Rounds
- round 1: E2E 견본 등록 실패(TS 꼬리 쉼표) → 파서 수정, pytest 편향 단정이 공유 DB 데이터에 의존 → 상대 조건으로
- round 2: 런타임 침해 판정 후 격리 목록이 비어 있음 → 스캐너가 host 격리, 시험에 격리·해제 단정 추가
- round 3: db_accounts 견본(usedBy=이름)·DDL 통과, network_policy 내부 평문 통과 → 견본 수정 + d9-04 DDL·d9-06 흐름별 mTLS. d9-06 첫 수정은 골든(메시 mTLS 안 평문)을 깨뜨려(오탐 10%) 흐름별 조건으로 좁힘

## 남은 것 / Notes
- 외부 도구(prowler·checkov·falco·tetragon·trivy·guarddog·lakeFS·sigstore·cilium·crowdsec)는 연동하지 않았다 — 결과를 점검 대상 모양으로 넣으면 같은 에이전트가 판정한다. L2 동적 심사·설치 시 동적 관찰은 L2 런타임이 없어 보류(격리 강등 없음).
- 메모리 복구 지점·되돌리기는 메모리 저장소 몫 — 플랫폼은 메타·판정·결정만 원장에.
