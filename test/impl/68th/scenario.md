# 68th — 봉인 해제 HSM (Epic 68 · 9차 한계 '봉인 해제기 = 별도 Shamir 노드' · NFR-D2 키 관리)

근거: 56th 클러스터는 봉인 해제기(transit, Shamir 로 사람이 풀기)에 기댄다. 운영 권고는 HSM(PKCS#11)·클라우드 KMS 자동 봉인 해제.
클라우드 KMS 는 이 환경 밖이므로 SoftHSM2(PKCS#11 소프트웨어 HSM) + OpenBao HSM 빌드(cgo)로 같은 설정 경로를 리허설한다.

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| C01 | 고정 판 | `make bao-hsm-up ENV=prod` | openbao-hsm 2.4.1 digest 고정(+hsm, cgo), SoftHSM2·OpenSC, 노드 TLS 잎 | P0 |
| C02 | 봉인 키 | 토큰 AegisMesh · 키 bao-unseal-rsa | 개인 키 민감·추출 불가·토큰 안 생성, PIN·SO PIN 비커밋 | P0 |
| C03 | 초기화 | sys/init 복구 키 3/2 | 봉인 방식 pkcs11 · recovery seal · 사람 없이 봉인 해제, 점검 비밀 쓰기·읽기 | P0 |
| C04 | 자동 봉인 해제 | 재기동 3회 | 사람 개입 없이 봉인 해제(시간 실측), 데이터 그대로 | P0 |
| C05 | HSM 없으면 못 푼다 | 틀린 PIN · 다른 토큰 · 틀린 키 이름 | 기동 거부(봉인 해제 불가) / 키 이름 오류의 실제 동작 기록 · 복귀 뒤 정상 | P0 |
| C06 | 회귀 | `make test` | 전부 통과(설정 일관성 시험 포함) | P0 |
