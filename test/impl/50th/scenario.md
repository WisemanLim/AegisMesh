# 50th — 유해 요청 포장 탐지 (Epic 50 · OQ9 · NFR-Q2)

근거: PRD.md OQ9 결정(D1-03 확장), 원본 PRD NFR-Q2(공개 코퍼스 미탐 1단계 ≤ 20%), 완료 게이트 BLOCKED 질문 답(2026-10-07):
**검증된 안전 분류 모델** — Qwen3Guard-Gen-0.6B(Alibaba Qwen, Apache-2.0, 비게이트, 고정 커밋 `fada3b2f…`)를 이미지 빌드 때 받아 자체 호스팅.
제약: 학습 데이터를 저장소에서 작성하지 않는다 · 공개 코퍼스는 평가 전용 · 인라인 예산(D1-03 30 ms, 입력 관문 p95 80 ms) 유지 →
모델은 CPU 에서 입력 1건 0.6~3 s 라 **응답 뒤 비동기 깊은 검사**(경보만, 차단 불가)로 둔다.

round 1: 학습 데이터 출처 미정으로 BLOCKED(완료 게이트에서 결정 요청). round 2 이하: 결정에 따라 재실행.

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| C01 | 단위 회귀 | `make test` | 전부 통과 (`test/test_guard.py`: 모델 신호·캐시·서버 장애 시 강등·응답 뒤 경보·대기 상한·코퍼스 deep 변형) | P0 |
| C02 | 모델 반입·무결성 | `infra/guard` 이미지 | 고정 커밋·파일 해시(SHA256SUMS)·PROVENANCE, 실행 중 네트워크 없음 | P0 |
| C03 | 탐지 능력 실측 | 공개 코퍼스 직접 입력 재생(측정 스크립트) | 주입·탈옥 미탐(인라인 ∪ 모델) ≤ 20%, 정상(XSTest 안전·GSM8K) 오탐 기록 | P0 |
| C04 | 지연·처리량 | 모델 서버 지연 분포 | 인라인 경로 지연 불변(모델은 응답 뒤), 모델 p50·p95·처리량 기록 | P0 |
| C05 | 응답 뒤 깊은 검사 | `make guard-up` → 판정 API | 인라인 판정 즉시 응답 · 모델 위험 판정만 Finding·원장 gate_async(deep) 경보 · 대기 상한 넘으면 건너뜀 집계 | P0 |
| C06 | 코퍼스 실측 반영 | `make corpus-eval`(deep 변형) | `/observability/slo` 에 인라인·깊은 검사 대표값 둘 다, 성공 지표는 깊은 검사 값 | P1 |
| C07 | prod 상호 TLS | `make guard-up ENV=prod` | api→guard https + 클라이언트 인증서, 인증서 없는 접속 거부 | P1 |
| C08 | 콘솔 | `/observability`·`/observability/slo` ko·en | 깊은 검사 통계·대표값, en 한글 0, 접근성 위반 0 | P1 |
