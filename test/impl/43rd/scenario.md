# 시험 시나리오 / Test Scenario — impl 43rd (Epic 43 공개 공격 코퍼스 실측)
- 근거: NFR-Q2 "공개 공격 코퍼스 미탐률 — JailbreakBench·HarmBench·garak 정기 실행, 1단계 ≤ 20%·정상 운영 ≤ 10%" · NFR-Q1(오탐) · R01 · 7차 결정: 이미지 빌드에서 고정 판, **평가 전용(학습 금지)**.
- 방식: `infra/corpus/Dockerfile` 이 GitHub 고정 커밋에서 데이터 파일만 받아 SHA256SUMS·PROVENANCE 와 함께 이미지에 둔다 → `corpus` 서비스가 `corpora` 볼륨에 복사 → api·worker 가 `/corpora` 읽기 전용. `app/corpora.py` 가 형식을 해석해 `quality.corpus_eval` 로 재생(변형 rules-only·dual × 배치 direct·indirect), 원장에는 해시·건수·범주별 비율·놓친 ID 만.
  - 주입·탈옥(목표 대상): JailbreakBench/artifacts@909e68c0(MIT — PAIR·GCG·JBC·무작위 탐색·DSN) · NVIDIA/garak@bb30a7e7(Apache-2.0 — DAN·야생 탈옥·TAP·시스템 프롬프트 추출)
  - 유해 요청(기법 없음, D1 대상 밖 — 참고): HarmBench@8e1604d1(MIT) · XSTest 위험 질문
  - 정상(오탐): XSTest@d7bb5bd7 안전 질문(CC-BY-4.0, 겉보기 위험) · GSM8K@3101c7d5 시험셋(MIT)
- 환경: local compose · `make corpus-eval` · plat.admin(화면)

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| T43-01 | 고정 판 반입 | 이미지 빌드 | 5개 저장소 고정 커밋·라이선스 PROVENANCE, 파일별 SHA-256 | P0 |
| T43-02 | 무결성 | 반입본 1파일 변조 | 실측 거부(409) | P0 |
| T43-03 | 형식 해석 | 원본 형식 그대로 | JBB jailbreaks.prompt(null·test-artifact 제외) · garak DAN 자리표시 치환 · CSV·JSONL | P0 |
| T43-04 | 실측 | 6 코퍼스 × 2 변형 × 2 배치 = 24 | 원장 기록 24건, 페이로드 미보존 | P0 |
| T43-05 | 이중 판정 효과 | rules-only vs dual | 주입·탈옥 미탐률 감소, 정상 오탐 증가 폭 | P0 |
| T43-06 | 대표값·지표 | 성공 지표·SLO | 공개·주입·dual·직접의 코퍼스별 최근값 가중 평균 — 정상 코퍼스가 최근이어도 깨지지 않음 | P0 |
| T43-07 | 화면 | `/observability/slo`·`/success` ko·en | 대표 카드·표(종류·엔진·배치·비율·출처), 접근성 위반 0, en 한글 0 | P1 |
| T43-08 | 정기 실행 | worker | 반입본 있으면 주 1회 실측 | P1 |
| T43-09 | 회귀 | JSONL 안 U+2028 · 전체 pytest | 업로드 정상 해석 · 전부 통과 | P0 |
