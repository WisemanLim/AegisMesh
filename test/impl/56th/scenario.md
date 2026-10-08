# 56th — OpenBao 운영 마감 + CLI 영어 (Epic 56 · 7차 한계 · NFR-C4)

근거: 7차(Epic 46) 운영형 리허설의 한계 — 단일 노드·수동 봉인 해제·평문 HTTP. NFR-C4 — 콘솔·보고서는 영어 완료, `aegis` CLI 출력은 한국어만.

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| C01 | 단위 회귀 | `make test` | 전부 통과 (test_openbao 장애 조치: 멈춘 노드·봉인 503 은 다음 노드, 시간 초과는 재전송 없음 / test_cli_i18n: en 명령·도움말 한글 0, ko 기본·환경 변수·플래그 우선) | P0 |
| C02 | 클러스터 구성 | `make bao-cluster-up ENV=prod` | 봉인 해제기(Shamir 3/2) → transit aegis-autounseal → 3노드 bao-1·2·3 자동 봉인 해제 · retry_join · 투표자 3 · api·worker 가 3주소·상호 TLS 로 임대 | P0 |
| C03 | 상호 TLS | 평문 HTTP · 인증서 없는 TLS · TLS 1.2 · 내부 CA 인증서 | 평문·무인증서·1.2 거부, 내부 CA 인증서만 성립 | P0 |
| C04 | 자동 봉인 해제 | 3노드 동시 재기동 | 운영자 개입 없이 전원 봉인 해제·리더 선출(시간 측정), 임대·raft 데이터 유지 | P0 |
| C05 | 리더 장애 | 리더 컨테이너 중지 | 새 리더 선출(시간), api 임대 발급·확인 계속(다른 노드로 장애 조치), 복귀 후 재가입 | P0 |
| C06 | 봉인 해제기 장애 | 봉인 해제기 중지 → 노드 1개 재기동 → 봉인 해제기 복구 | 운영 중 노드는 계속, 재기동 노드는 봉인 유지 → 봉인 해제기 봉인 해제 뒤 스스로 풀림 | P1 |
| C07 | CLI 영어 | `aegis --lang en …` · `AEGIS_LANG=en` | list·eval·coverage·verify-bundle·airgap·sbom·a2a·도움말 영어, JSON 은 그대로 | P0 |
