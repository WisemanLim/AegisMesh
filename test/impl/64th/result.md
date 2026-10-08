# 시험 결과 / Test Result — impl 64th (Epic 64 인라인 소형 분류 모델)
- 일자: 2026-10-08 · 대상: local (Docker Desktop arm64 VM, 8 vCPU) · injguard = deberta-v3-base-prompt-injection-v2 @90c9989b ONNX(sha256 f0ea7f23…) · ORT 1.22.1 CPU · 커밋: —

## 요약 / Summary
- 전체 8, 통과 8, 실패 0 → 최종 **PASS** (재시도 4회: PyTorch CPU 지연 → ORT / 토크나이저 512 자르기 → 앞·뒤 창 / **한국어 정상 문장 오탐 → 라틴 문자 입력만 모델** / 배치 env 가 시험에 샘)
- 공개 코퍼스(직접 입력) 미탐: JailbreakBench **50.4% → 28.0%**, garak 주입 **26.6% → 14.0%** · 정상 오탐 xstest-safe 0.4% · gsm8k 0.1% 그대로
- 인라인 지연: 창 96 토큰(앞 48 + 뒤 48) · 8 스레드 — 모델 p95 ≈ 49 ms, 관문 실행 p95 19.9 ms(부하·한국어 혼합), 순차 600건 시간 초과 2건(모델 신호 없이 이중 판정)
- 배치: `make injguard-up` → `ENGINE_OVERRIDES=d1-03=injection_model` — 실제 관문에서 D1-03 v1.3.0 엔진 injection_model, 근거 `주입 분류 모델 1.000 · 창 28 토큰`

## 구현
- `infra/injguard/` — Dockerfile(모델 커밋·파일 목록·ONNX sha256 고정, 비루트) · `server.py`(토크나이저 자르기 끔 → 앞·뒤 창, ORT 세션, `/classify`·`/health`, TLS_DIR 이면 상호 TLS)
- D1-03 엔진 `injection_model`(기본 = 이중 판정 + 모델) — 경보 ≥ 0.95(`model`) · 차단 ≥ 0.999(`model-block`), 같은 위치 규칙 신호가 있으면 규칙이 주 근거(모델 점수 0.79 상한), 같은 입력은 메모리 캐시, 글자 중 라틴 비율 < 0.8 이면 모델을 묻지 않음
- 배치: `ENGINE_OVERRIDES`(에이전트 기본 엔진 교체, 없는 엔진은 무시) · 코퍼스 `dual` 은 jailbreak_classifier 로 고정(교체와 무관한 비교 기준), 규칙 전용 = 분류기·모델 없는 엔진
- `make injguard-up|down [ENV=prod]` · `make corpus-eval VARIANTS=… MODES=…` · `make loadtest UNIQUE=1`(입력마다 무작위 꼬리 — 캐시 비켜 실제 모델 호출)
- `test/test_injguard.py` 5건(임계·규칙 우선·캐시 / 비라틴 생략 / 시간 초과 / URL 없음 = 분류기 / 기본 엔진 교체)

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | `injguard-up.txt` 빌드·healthy · prod 는 tls subpath injguard(인증서 없으면 거부 — 완료 게이트 prod 회귀에서 재확인) |
| C02 | PASS | `c02-window-sweep.txt`(400단어 입력, 순차) 창 32/64/96/128/192 p95 22/44/53/66/109 ms → 모델 시간 초과(60 ms) 안 최대 = **96** · `score-dist.txt` 임계별 탐지(0.95 / 0.999) |
| C03 | PASS | `c10-corpus-eval-latin.txt` 위 요약 · 간접(세그먼트) 재생은 변화 없음 — D1-03 범위가 사용자 text 뿐(세그먼트는 D1-01·D1-02) |
| C04 | PASS | `c04-timeouts.txt` 600건 시간 초과 2 · 오류 0 · 판정 p50 27.2 / p95 62.2 ms · 단위 시험 `test_timeout_keeps_dual_verdict…` |
| C05 | PASS | `c06-judge-api.txt` engine injection_model · v1.3.0 · d1-03 17 ms |
| C06 | PASS | round 3 — `c08-korean-probe.txt` 모델 원점수: 한국어 정상 문장 0.998~1.000, 영어 0.000 · 게이트 전 `c07-loadtest-model.txt` 차단 826/1447 → 게이트 뒤 `c08-loadtest-latin.txt` 차단 306/2868 = 공격 비율(10%)만 |
| C07 | PASS | 오류 0/2868 · 관문 실행 p95 19.9 ms / 예산 80 · `c09-model-capacity.txt` 모델 서버 1 스트림 31.5 rps(p95 45 ms, 60 ms 초과 0) · 동시 4 이상은 60 ms 초과 → 초과분은 이중 판정 |
| C08 | PASS | `make-test.txt` 473 passed |

## 회차 / Rounds
- round 1: PyTorch CPU 추론 p95 수백 ms, int8 동적 양자화는 탐지가 무너짐 → ONNX Runtime(같은 가중치) 로 교체
- round 2: 토크나이저 기본 512 자르기·패딩 → 끄고 앞·뒤 창(긴 탈옥 문의 끝에 붙은 요청까지 봄)
- round 3: 부하 시험에서 정상 한국어 입력이 대량 차단 — 모델이 영어 학습(한국어 정상 문장 0.998+) → 라틴 문자 비율 0.8 미만 입력은 모델 생략(규칙·분류기는 한국어 포함). 생략 건수 `STATS.skipped`, explain 의 `latin`
- round 4: `make test` 1건 실패(test_corpora 행 수 36 ≠ 24) — 시험 컨테이너가 injguard-up 의 api.env(INJGUARD_URL·ENGINE_OVERRIDES)를 물려받음 → conftest 에서 비움(GUARD_URL 과 같은 방식)

## 남은 것 / Notes
- 한국어 등 비라틴 입력에는 모델 효과 없음 — 다국어 주입 모델(고정 판·허용 라이선스) 확보 시 교체. 영어 코퍼스 수치만 개선분
- 모델 서버 처리 한계 ≈ 30 rps(예산 안, 8 vCPU 공유) — 넘는 입력은 이중 판정으로 통과 판정(인라인 차단을 늦추지 않음). 인라인 범위를 넓히려면 injguard 복제·전용 노드
- 간접 주입(세그먼트)에 같은 모델을 쓰는 것은 D1-01 엔진 몫 — 이번 범위 밖
