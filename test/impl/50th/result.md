# 시험 결과 / Test Result — impl 50th (Epic 50 유해 요청 포장 탐지, OQ9 · NFR-Q2) + 8차 완료 게이트
- 일자: 2026-10-07 · 대상: local + prod 리허설(PostgreSQL 17, 상호 TLS) · 모델: Qwen3Guard-Gen-0.6B @ `fada3b2f655b` (Apache-2.0) · 커밋: —

## 요약 / Summary
- 전체 8, 통과 8, 실패 0 → 최종 **PASS** (round 1 BLOCKED → 완료 게이트 질문 답 "검증된 안전 분류 모델" → round 2~6)
- **공개 코퍼스 주입·탈옥 미탐 41.1% → 9.7%** (JailbreakBench 50.4 → 8.0% · garak 26.6 → 12.4%, `make corpus-eval` deep 변형) — NFR-Q2 1단계(≤ 20%)·정상 운영(≤ 10%) 충족. 범주별: PAIR 86 → 11% · GCG 88 → 18% · DSN 89 → 13%
- 대가: 정상 입력 오탐 — 골든셋 1,000건 **0%** · GSM8K 0.1%(인라인과 같음) · XSTest 안전(일부러 위험해 보이게 만든 정상 질문) **5.2%**. 깊은 검사는 응답 뒤 경보만이라 인라인 차단 오탐(NFR-Q1)에는 영향 없음
- 모델은 CPU 에서 p50 1.1 s · p95 4.0 s(최대 10.9 s, 실측 3,959건) — 인라인 예산(30 ms)에 못 들어가 **응답 뒤 비동기 깊은 검사**. 처리량은 복제본 2개 합 초당 약 1.6건 → 넘치는 요청은 대기 상한에서 건너뛰고 센다(`deepCheck.skipped`)
- 학습 데이터는 작성하지 않았다. 공개 코퍼스는 평가 전용 그대로(모델 학습·임계 학습에 쓰지 않음, 하한만 실측 표로 고름)
- `make test` 429 passed · `make test-web` 15 + tsc · 접근성 256쪽 위반 0·129/129·54/54 · 계약 221 · prod 회귀 통과

## 구현
- `infra/guard/` — 이미지 빌드 때 고정 커밋 가중치를 받고 허브 LFS 해시(`4f3ce47e…`)로 검증, `SHA256SUMS`·`PROVENANCE`, 실행 중 네트워크 없음(HF_HUB_OFFLINE). `server.py`: 모델 카드 지시문의 고정 앞부분(202 토큰) KV 캐시 + "Safety:" 뒤 첫 토큰 확률 1회 순전파(생성 방식과 등급 일치 확인), 위험일 때만 범주 생성, 입력 로그 없음, `TLS_DIR` 이면 클라이언트 인증서 필수
- compose `guard`(프로파일 `guard`, TLS 인지 헬스 검사) · prod 덧씌움(볼륨 `tls` 하위 경로 `guard`, `scripts/certs.py` 말단 추가) · `make guard-up|guard-down [ENV=prod]`(`infra/guard/api.env`, 비커밋)
- D1-03 엔진 `jailbreak_guard`(규칙 + n-gram 분류기 + 모델, 입력 캐시, 서버 장애 = 예외 → failMode) · 규칙 `D1-03.guard`(경보) · 매니페스트 1.2.0 · 영문 규칙
- `app/gating.run_deep` — 전용 실행기(작업 `GUARD_WORKERS`)·대기 상한 `GUARD_QUEUE_MAX`, 모델이 새로 잡은 것만 Finding + 원장 `gate_async`(deep) · `/v1/observability` `deepCheck` · 콘솔 관측 화면 통계
- 코퍼스 `deep` 변형(`/v1/quality/corpora` variant, `make corpus-eval` 은 GUARD_URL 있으면 자동, 간접 배치 생략·병렬) · 대표값 `corpusHeadline`(인라인)·`corpusHeadlineDeep` · 성공 지표 미탐률은 깊은 검사 값 · SLO 화면 두 값
- env `GUARD_URL`·`GUARD_UNSAFE_MIN`(0.5)·`GUARD_QUEUE_MAX`·`GUARD_THREADS` · `test/conftest.py` GUARD_URL 고정 · `test/test_guard.py` 6건 · `app/corpora.py` 코퍼스·변형 행마다 커밋

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | `make test` 429 passed · test_guard 6 (모델 신호·캐시·인라인 엔진은 모델 안 부름·서버 장애 시 강등·응답 뒤 경보·대기 상한·deep 변형) |
| C02 | PASS | PROVENANCE `Qwen/Qwen3Guard-Gen-0.6B fada3b2f… Apache-2.0` · SHA256SUMS 8/8 OK · 빌드 단계 `model.safetensors: OK` · HF_HUB_OFFLINE=1 |
| C03 | PASS | 하한별 표(logs/c03-analysis.txt): 0.5 → 미탐 9.74%·XSTest 안전 5.2%·골든 0% / 0.8 → 15.5%·2.8% / 0.9 → 19.9%·2.4% / 0.95 → 23.8%·1.2%. 기본 0.5 |
| C04 | PASS | 인라인 경로 3~56 ms(local)·11~138 ms(prod, 클라이언트 측 TLS 포함) — 모델을 기다리지 않음. 모델 p50 1,120 · p95 3,972 · 최대 10,895 ms · 컨테이너당 메모리 약 4 GB |
| C05 | PASS | local guard-up: 실측에서 '인라인 통과·모델 위험'이던 공격 5건 → 응답 뒤 경보 5/5, 정상 5건 0 · deepCheck submitted 20·checked 20·skipped 0·failed 0 |
| C06 | PASS | `make corpus-eval`(2:30): deep jailbreakbench 8.0%·garak 12.4%·HarmBench 9.2%·XSTest 위험 21.0% / XSTest 안전 FP 5.2%·GSM8K 0.1% · `corpusHeadline` 0.4112 · `corpusHeadlineDeep` 0.0974 · 성공 지표 9.74 met(deep) |
| C07 | PASS | prod guard-up: `guard ready … tls=True` · 인증서 없이 TLSV13_ALERT_CERTIFICATE_REQUIRED · 평문 연결 끊김 · api 인증서 200 · 깊은 검사 공격 5/5 경보·정상 0 |
| C08 | PASS | `/observability`·`/observability/slo` ko·en 위반 0 · en 한글은 기존 마스킹 예시(textarea)뿐(새 TLS 구간 문구 누락 1건 게이트에서 수정) |

## 회차 / Rounds
- round 1: 유해 요청 라벨 학습셋을 자체 작성하지 않기로 해 BLOCKED → 완료 게이트 질문 → "검증된 안전 분류 모델"
- round 2: 모델 카드 방식(생성 24 토큰) 2.9 s/건 → "Safety:" 뒤 첫 토큰 확률 1회 순전파 + 고정 지시문 KV 캐시(확률 일치 확인) → 0.6 s(짧은 입력)
- round 3: 1차 실측 스크립트가 등급만 세 하한을 고를 근거 부족 → 건별 ID·확률 JSONL(문장 없음)·범주 생성 생략·복제본 2개
- round 4: 시험 컨테이너가 `infra/guard/api.env` 의 GUARD_URL 을 물려받아 corpus 시험이 deep 변형까지 돎(test_corpora 실패) → conftest 에서 비움(OpenBao 때와 같은 유형)
- round 5: `make corpus-eval` 1회차 33분 뒤 137 — 같은 호스트의 다른 프로젝트가 로컬 스택 컨테이너를 지움(OOM 아님). 끝난 행도 다 잃는 구조 → 코퍼스·변형 행마다 커밋, `make local-all` 후 재실행(2:30)
- round 6: 게이트 크롤에서 en `/observability` 의 새 TLS 구간 설명 한글 1건 → 영문 사전 추가, 해당 화면 재검사 위반 0·한글 0

## 남은 것 / Notes
- 처리량: CPU 복제본 1개당 초당 1건 안팎 — 운영 트래픽(수백 rps)에서는 대부분 건너뛴다(집계는 보임). 전부 검사하려면 GPU·복제본 증설 또는 표본·선별 정책이 필요하다.
- 인라인 차단 기준 미탐은 41.1% 그대로다. 깊은 검사는 응답 뒤 경보라 이미 나간 응답을 막지 못한다.
- XSTest 안전 5.2% 경보 — 하한을 0.8 로 올리면 2.8%(미탐 15.5%). 운영에서 경보 피로를 보고 `GUARD_UNSAFE_MIN` 조정.
- 로컬 기본값은 깊은 검사 꺼짐(`make guard-up` 으로 켬). guard 이미지 약 4 GB.
