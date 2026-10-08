# 시험 시나리오 / Test Scenario — impl 42nd (Epic 42 소형 분류기 이중 판정)
- 근거: FR-D1-01 "인젝션 분류기 이중 판정" · FR-D1-03 "탈옥 코퍼스 유사도 매칭 + 전용 분류기" · 원본 Q1(규칙 + 소형 분류기) → **OQ4 결정(2026-10-07): 자체 경량 분류기** · NFR-L(인라인 지연) · R01(오탐).
- 방식: `aegis/classifier.py` — NFKC·소문자·leet 정규화 → 글자 3·4-gram + 단어 1·2-gram, CRC32 해시 2^18, 로지스틱 회귀(순수 파이썬). 학습 `scripts/train_classifier.py` = 합성 학습셋(`aegis/trainset.py`, 한·영, 어려운 정상 포함) + D1 에이전트 시험셋 + 골든셋 생성기(다른 seed). **공개 코퍼스 학습 금지**(43차 평가 전용). 가중치 `aegis/data/injection-clf-v1.json`(무결성 해시 내장) — 엔진이 해시를 고정, 다르면 적재 거부.
  D1-01 `spotlight_classifier`(규칙 + 신뢰할 수 없는 조각 점수) · D1-03 `jailbreak_classifier`(코퍼스 규칙 + 사용자 입력 점수). 경보 ≥ 0.8 → `classifier`(alert), 차단 ≥ 0.95 → `classifier-block`(block). 같은 위치에 규칙이 걸리면 규칙이 주 근거. 규칙 전용 엔진은 그대로 남겨 비교 가능.
- 환경: local compose · plat.admin

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| T42-01 | 무결성 고정 | 기대 해시 불일치·가중치 1칸 변조 | 적재 거부(ModelIntegrityError) | P0 |
| T42-02 | 재현성 | 같은 seed 재학습 | 같은 가중치 해시 | P1 |
| T42-03 | 이중 판정 | 규칙 정규식 밖 의역 공격 | 규칙 전용 allow → 이중 alert(classifier), 근거 메모 = 점수 | P0 |
| T42-04 | 규칙 우선 | 규칙·분류기 모두 걸림 | ruleId = 규칙(override/dan), 분류기는 추가 근거 | P1 |
| T42-05 | 시험셋 회귀 | D1-01·D1-03 attacks/golden | 공격 전부 탐지·정상 전부 allow | P0 |
| T42-06 | 골든셋 오탐 | 1만 건 재생 | ≤ 0.5%, 초과 에이전트 0 | P0 |
| T42-07 | 지연 | 3,000자 조각·짧은 문장 120건 | p95 < 에이전트 예산 30ms | P0 |
| T42-08 | 설명 | 검사기(explain) | 조각별 점수·임계·모델 해시·읽을 수 있는 특징 | P1 |
| T42-09 | 보류 표본 효과 | 학습에서 뺀 15% (합성) | 규칙 전용 대비 탐지율·오탐 변화 수치 | P1 |
| T42-10 | 실서비스 경로 | `/v1/judge:batch`·`/v1/agents/{id}:inspect`(engine 지정)·콘솔 검사기 ko·en | 관문 alert · 규칙 전용 allow · 콘솔 분류기 줄 표시 | P0 |
| T42-11 | 영어·회귀 | 새 규칙 4개 영어 · 전체 pytest | rules.en 일치 · 전부 통과 | P0 |
