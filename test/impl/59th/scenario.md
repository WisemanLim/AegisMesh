# 59th — 외부 레드팀 엔진 garak 어댑터 (Epic 59 · 의존성 '탐지 엔진 오픈소스·교체 가능')

근거: README 후속 '외부 탐지 엔진(garak) 어댑터'. 43차부터 garak **데이터**는 코퍼스 평가에 썼지만, garak **도구**(탐침·탐지기·보고서)를 돌린 적은 없다.

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| C01 | 단위 회귀 | `make test` | 전부 통과 (test_garak: 보고서 JSONL → 탐침·탐지기별 무방비·관문 ASR, 원장·API 에 페이로드 없음, 대상 shim 의 입력 차단 거절·출력 변환) | P0 |
| C02 | 고정 판 | `infra/garak` 이미지 빌드 | garak 0.13.1(이미지 빌드에서만 네트워크, aarch64 휠은 Rust 빌더 스테이지) | P0 |
| C03 | 실행 | `make garak-scan OUT=…` | 같은 탐침 12종을 무방비(test.Repeat)·관문 뒤(garak-target → /v1/judge:batch) 에, 보고서 2개 → 원장 quality `garak_scan` | P0 |
| C04 | 결과 표시 | `GET /v1/quality/garak` · `/observability/slo` | garak 판·전체·탐침별 ASR | P1 |
