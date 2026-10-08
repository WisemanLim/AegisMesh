# 시험 결과 / Test Result — impl 59th (Epic 59 외부 레드팀 엔진 garak 어댑터)
- 일자: 2026-10-08 · 대상: local + garak 0.13.1(고정 판) · 커밋: —

## 요약 / Summary
- 전체 4, 통과 4, 실패 0 → 최종 **PASS** (재시도 1회: base2048 aarch64 휠 없음 → Rust 빌더 스테이지)
- 같은 탐침 12종(2,934 시도)을 무방비 모델(되풀이)과 AegisMesh 관문 뒤 같은 모델에 — 공격 성공률(ASR) **45.3% → 24.7%**
- 관문이 막은 것: promptinject(지시 탈취) HijackHateHumans 100% → 19.1% · HijackKillHumans 100% → 24.2% · HijackLongPrompt 100% → 20.3%
- **관문 뒤에도 그대로(실측 공백)**: latentinjection Report·Resume 100% → 100%(문서 속 숨은 지시 — D1 미탐) · exploitation Jinja·SQLi 되풀이 100% → 100%(보호 대상 프로파일 chatbot-baseline 에 D3 도구·명령 에이전트 없음) · ansiescape.AnsiRaw 36.2% → 36.2%(출력의 ANSI 제어 문자 — 해당 탐지 없음) · encoding·goodside.Tag 는 되풀이 모델이라 0%(참고값 아님)
- 원장·API·콘솔(SLO 화면 'garak')에 garak 판·탐침별 ASR — 탐침 페이로드·응답 원문은 보관 안 함(hitlog 는 시험 로그에만)

## 구현
- `infra/garak/Dockerfile`(garak 0.13.1 + CPU torch, base2048 휠 = 고정 판 Rust 빌더 스테이지) · `garak.yaml`(보고서 /out, 병렬 8) · `rest.json`(REST 생성기 → garak-target)
- `scripts/garak_target.py`(무방비 되풀이 모델 앞뒤에 입력·출력 관문 — 차단·승인 필요 = 거절, 변환 = 변환 출력) · compose local 프로파일 `garak`(garak·garak-target)
- `app/garak.py` setup(서비스 계정 svc.garak 토큰 6시간 → 비커밋 `infra/garak/target.env`, 보호 대상 garak.demo 에 chatbot-baseline enforce) · ingest(보고서 → 원장 quality `garak_scan`) · `GET /v1/quality/garak` · SLO 화면 · Makefile `garak-scan [OUT] [GARAK_PROBES]` · `test/test_garak.py` 2

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | test_garak 2 · `make test` (게이트에서 전체) |
| C02 | PASS | garak-scan.txt 이미지 `garak LLM vulnerability scanner v0.13.1` |
| C03 | PASS | garak-scan.txt 마지막 JSON · baseline·guarded report.jsonl/html · 원장 seq 401654 |
| C04 | PASS | `/v1/quality/garak` latest 0.13.1 · 16 탐침·탐지기 쌍 · SLO 화면 구역 `garak` |

## 회차 / Rounds
- round 1: garak 의존성 base2048 은 linux/aarch64 휠이 없어 Rust 필요 → `rust:1.89-slim-trixie` 툴체인을 빌더 스테이지에만 두고 휠만 넘김

## 남은 것 / Notes
- 공백 3가지(문서 속 숨은 지시, 도구 없는 프로파일의 템플릿·SQL 되풀이, ANSI 제어 문자)는 탐지 품질 후속 — 도구를 쓰는 보호 대상은 D3 포함 프로파일로 다시 재면 된다(`GARAK_PROBES`·프로파일 교체).
- garak 은 local 리허설 전용(운영 트래픽과 분리). 실행 중 모델 내려받기 없는 탐침·탐지기만 기본값.
