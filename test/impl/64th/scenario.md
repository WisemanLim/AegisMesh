# 64th — 인라인 소형 분류 모델 (Epic 64 · NFR-Q2 인라인 · OQ9 · 9차 한계 '규칙·소형 분류기가 놓치는 탈옥')

근거: 50th 의 깊은 검사(Qwen3Guard, 응답 뒤 비동기)는 인라인 예산(입력 관문 80 ms) 밖이다. 인라인 경로의 D1-03 은 규칙 + 소형
분류기(이중 판정)뿐이라 JailbreakBench 의 PAIR·GCG·DSN 류를 절반 가까이 놓쳤다(50th: 미탐 50.4%).
고정 커밋 주입 분류 모델(protectai/deberta-v3-base-prompt-injection-v2, Apache-2.0)을 ONNX Runtime CPU 로 compose 서비스 `injguard`
에 두고, D1-03 엔진 `injection_model` 이 예산 안에서 묻는다. 시간 초과·장애 시 모델 신호 없이 이중 판정으로(관문을 막지 않음).

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| C01 | 고정 판 모델 서비스 | `make injguard-up` | 커밋·ONNX sha256 고정 이미지 빌드, `/health` OK, prod 는 상호 TLS | P0 |
| C02 | 지연 예산 | 창(앞·뒤 토큰) 32~192 × 스레드 | 입력 관문 예산(80 ms) 안 p95 를 주는 창 선택 | P0 |
| C03 | 공개 코퍼스 탐지·오탐 | `make corpus-eval VARIANTS=dual,model MODES=direct,indirect` | 주입 미탐 감소, 정상 오탐 증가 없음 | P0 |
| C04 | 시간 초과 처리 | 순차 600건 · 가짜 느린 서버 | 시간 초과는 모델 신호 없이 이중 판정, 강등(degraded) 아님 | P0 |
| C05 | 배치 | `ENGINE_OVERRIDES=d1-03=injection_model`(injguard-up 이 넣음) | 실제 관문 경로 D1-03 엔진 = injection_model, 판정 근거에 모델 점수 | P0 |
| C06 | 비영어 입력 | 한국어 정상 문장 | 영어 모델의 오탐이 관문 판정에 들어가지 않음 | P0 |
| C07 | 부하 아래 | `make loadtest MIX=input:1 UNIQUE=1` · 모델 서버 동시성 | 오류 0, 관문 실행 p95 예산 안, 모델 처리 한계 기록 | P1 |
| C08 | 회귀 | `make test` | 전부 통과 (엔진 단위 시험 5건 포함) | P0 |
