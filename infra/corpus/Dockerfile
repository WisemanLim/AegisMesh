# 공개 공격 코퍼스 (Epic 43 · NFR-Q2) — GitHub 고정 커밋에서 데이터 파일만 받아 /corpora 에 둔다.
# 평가 전용(분류기 학습 금지) · 저장소에는 커밋하지 않는다 · 각 파일 SHA-256 과 출처 커밋을 PROVENANCE 에 남긴다.
FROM alpine/git:2.47.2 AS fetch
ARG JBB_ARTIFACTS=909e68c01d94222b8ad2e397a017e2e12e2adb73
ARG GARAK=bb30a7e79f4e78ef633a92295f142105a0e69941
ARG HARMBENCH=8e1604d1171fe8a48d8febecd22f600e462bdcdd
ARG XSTEST=d7bb5bd738c1fcbc36edd83d5e7d1b71a3e2d84d
ARG GSM8K=3101c7d5072418e28b9008a6636bde82a006892c
# JailbreakBench 공격 산출물(PAIR·GCG·JBC·무작위 탐색·DSN) — MIT
RUN git init -q /src/jailbreakbench && cd /src/jailbreakbench && git remote add o https://github.com/JailbreakBench/artifacts \
 && git fetch -q --depth 1 o $JBB_ARTIFACTS && git checkout -q FETCH_HEAD -- attack-artifacts LICENSE && rm -rf .git
# garak 탐침 데이터(DAN 계열·야생 탈옥·TAP·시스템 프롬프트 추출) + 정상 지시문(오탐 측정) — Apache-2.0
RUN git init -q /src/garak && cd /src/garak && git remote add o https://github.com/NVIDIA/garak \
 && git fetch -q --depth 1 --filter=blob:none o $GARAK \
 && git checkout -q FETCH_HEAD -- garak/data/dan garak/data/inthewild_jailbreak_llms.json garak/data/tap/tap_jailbreaks.txt \
      garak/data/sysprompt_extraction/attacks.json garak/data/payloads/normal_instructions.json LICENSE && rm -rf .git
# HarmBench 텍스트 행동(유해 요청 — 주입·탈옥 기법 없음, D1 대상 밖으로 별도 보고) — MIT
RUN git init -q /src/harmbench && cd /src/harmbench && git remote add o https://github.com/centerforaisafety/HarmBench \
 && git fetch -q --depth 1 --filter=blob:none o $HARMBENCH \
 && git checkout -q FETCH_HEAD -- data/behavior_datasets/harmbench_behaviors_text_all.csv LICENSE && rm -rf .git
# XSTest — 겉보기엔 위험한 안전 질문 250 + 위험 질문 200(오탐·과잉 차단 측정) — CC-BY-4.0
RUN git init -q /src/xstest && cd /src/xstest && git remote add o https://github.com/paul-rottger/exaggerated-safety \
 && git fetch -q --depth 1 --filter=blob:none o $XSTEST && git checkout -q FETCH_HEAD -- xstest_prompts.csv LICENSE && rm -rf .git
# GSM8K 시험셋 — 일상 문장 수학 질문 1,319(일반 정상 입력 오탐 측정) — MIT
RUN git init -q /src/gsm8k && cd /src/gsm8k && git remote add o https://github.com/openai/grade-school-math \
 && git fetch -q --depth 1 --filter=blob:none o $GSM8K && git checkout -q FETCH_HEAD -- grade_school_math/data/test.jsonl LICENSE && rm -rf .git
RUN cd /src && printf 'jailbreakbench JailbreakBench/artifacts %s MIT\ngarak NVIDIA/garak %s Apache-2.0\nharmbench centerforaisafety/HarmBench %s MIT\nxstest paul-rottger/exaggerated-safety %s CC-BY-4.0\ngsm8k openai/grade-school-math %s MIT\n' \
      $JBB_ARTIFACTS $GARAK $HARMBENCH $XSTEST $GSM8K > PROVENANCE && find . -type f ! -name SHA256SUMS | sort | xargs sha256sum > SHA256SUMS

FROM alpine:3.20
COPY --from=fetch /src /corpora
# 실행 = 공유 볼륨(/out)에 복사 — api 가 /corpora 로 읽기 전용 마운트해 오프라인 평가
CMD ["sh", "-c", "rm -rf /out/* && cp -a /corpora/. /out/ && wc -l /out/SHA256SUMS && cat /out/PROVENANCE"]
