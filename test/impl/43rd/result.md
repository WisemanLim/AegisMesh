# 시험 결과 / Test Result — impl 43rd (Epic 43 공개 공격 코퍼스 실측)
- 일자: 2026-10-07 · 대상: local compose + 공개 코퍼스 고정 판 이미지 · 커밋: —

## 요약 / Summary
- 전체 9, 통과 9, 실패 0 → 최종 **PASS** (재시도 3회: JSONL 줄 분리 실결함 / 성공 지표 코퍼스 선택 실결함 / 화면 en 문구 2건). **판정은 '측정 체계 PASS' 이고, 측정된 미탐률은 NFR-Q2 목표 미달이다.**
- `make test` 403 passed · `test_corpora` 4 · `make test-web` 15 + tsc · 실측 로그(logs/run-r2·r3.txt, 같은 수치 재현) · 화면(logs/slo-shot.txt, slo-corpora-ko·en.png)
- **실측 (배포 엔진 = 규칙 + 분류기, 직접 입력)**:
  | 코퍼스 | 종류 | 건수 | 규칙만 | 이중 판정 |
  |---|---|---|---|---|
  | JailbreakBench 공격 산출물 | 주입·탈옥 | 1,097 | 미탐 72.9% | **미탐 50.4%** (PAIR 86 · GCG 88 · DSN 89 · JBC 0 · 무작위 탐색 0) |
  | garak (DAN·야생·TAP·추출) | 주입·탈옥 | 700 | 미탐 63.7% | **미탐 26.6%** (야생 27 · DAN 8 · TAP 11 · 추출 0~100) |
  | **대표값(가중)** | | 1,797 | — | **41.1%** — 목표 1단계 ≤ 20%·정상 운영 ≤ 10% **미달** |
  | HarmBench 행동 | 유해 요청(참고) | 393 | 100% | 90.3% |
  | XSTest 위험 | 유해 요청(참고) | 200 | 100% | 99.5% |
  | XSTest 안전 | 정상 | 250 | 오탐 0.0% | 오탐 0.4% |
  | GSM8K 시험셋 | 정상 | 1,319 | 오탐 0.0% | 오탐 0.1% |
  간접 배치(웹 조각)는 JailbreakBench 50.3% · garak 21.7%.
- 측정으로 찾은 사실: (1) 그동안의 합성 지표(미탐 5.9%)는 크게 낙관적이었다. (2) 분류기(42차)는 공개 코퍼스에서 미탐을 22~37%p 줄이고 정상 오탐은 0.1~0.4% 늘렸다. (3) 놓치는 것은 지시 덮어쓰기 표식이 없는 '유해 요청 포장'(설득형 PAIR·적대 접미사 GCG·DSN) — 현재 D1 탐지기(주입·탈옥 기법 탐지)와 별개인 '유해 요청 의도 분류' 영역이다.
- 실결함 2건 수정: `quality._items` 가 `str.splitlines()` 로 JSONL 을 나눠 문자열 안 U+2028·U+0085 에서 정상 JSON 을 깨뜨림(공개 코퍼스 68행에서 발견, API 업로드도 해당) / 성공 지표가 '가장 최근 코퍼스 기록'을 읽어 정상 코퍼스가 최근이면 KeyError

## 구현
- `infra/corpus/Dockerfile`(고정 커밋 5개·SHA256SUMS·PROVENANCE) · compose `corpus` 서비스 + `corpora` 볼륨(api·worker `/corpora:ro`) · `make corpus-eval`
- `app/corpora.py`(무결성 확인·형식 해석·실측 실행·CLI 표) · `quality.corpus_eval` 확장(kind attack/benign · variant dual/rules-only · scope injection/harmful-request) · `quality.rules_only_engines` · `quality.corpus_headline` · 성공 지표 miss-rate = 대표값 · worker 주 1회 · API `kind`·`variant`·`scope`
- `/observability/slo` 대표 카드·코퍼스 표·반입 종류 선택 · 설정 `CORPORA_DIR`·`CORPUS_INTERVAL_SEC`(.env 3곳)
- `test/test_corpora.py`(가짜 반입본으로 해석·무결성·비교·대표값·U+2028)

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T43-01 | PASS | PROVENANCE 5행(커밋·라이선스 MIT·Apache-2.0·CC-BY-4.0 — LICENSE 파일 머리로 확인) · SHA256SUMS 56 |
| T43-02 | PASS | 가짜 반입본 1파일 변경 → integrity false · run 409 |
| T43-03 | PASS | JBB 1,097(중복·null·test-artifact 제외) · garak 700 · HarmBench 393 · XSTest 200/250 · GSM8K 1,319 |
| T43-04 | PASS | 24건 원장(quality corpus:*) · payloadStored false · 실행 약 15초 |
| T43-05 | PASS | 위 표 |
| T43-06 | PASS | corpusHeadline 0.4112 (garak 0.2657 · jailbreakbench 0.5041) · 성공 지표 miss-rate 41.12 '미달' (logs/headline.txt) |
| T43-07 | PASS | ko·en 대표 카드·표 · 접근성 128쪽 위반 0 · 41/41 · en 한글 0 |
| T43-08 | PASS | 코드 확인 — worker `_due_quality("corpus:%", 604800)` 이고 반입본이 무결할 때만 `corpora.run` (자동 시험은 없음, 실행 후 다음 주기까지 대기) |
| T43-09 | PASS | U+2028·U+0085 포함 JSONL 2건 정상 해석 · 403 passed |

## 회차 / Rounds
- round 1: `make corpus-eval` 첫 실행이 68행 JSON 오류 — `_items` 의 `splitlines()` 가 문자열 안 U+2028 에서 자름 → `\n` 로만 분리, 회귀 시험 추가
- round 2: 정상 코퍼스가 마지막으로 기록되자 성공 지표가 그 기록의 `missRate` 를 읽으려다 실패할 구조 → `corpus_headline`(공개·주입·dual·직접, 코퍼스별 최근값 가중)으로 교체, SLO 카드도 같은 값
- round 3: `/findings/[id]` 이의 방식 '사람 검토 + 교차 재판정'·SLO 언어별 줄·'(편입 표본)' 이 en 에서 한국어 → 카탈로그·tr, 운영자가 적은 코퍼스 출처는 `data-user`

## 남은 것 / Notes
- NFR-Q2 목표 미달(41.1%). 개선 후보: 유해 요청 의도 분류기(주입 기법과 별개), 적대 접미사 탐지 강화(D1-03 휴리스틱은 경보만), 학습 다양성 확대 — 공개 코퍼스는 평가 전용 원칙을 유지한다(OQ4). PRD Open Questions 에 기록.
- 간접 배치에서 garak 미탐이 더 낮은 것은 D1-01(신뢰할 수 없는 조각) 이 함께 판정하기 때문.
