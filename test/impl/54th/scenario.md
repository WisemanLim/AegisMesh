# 54th — 보안 키 증명 체인 (Epic 54 · OQ3 AAGUID 허용목록)

근거: OQ3 결정(테넌트 인증기 AAGUID 허용목록) — 지금까지는 인증기가 스스로 밝힌 AAGUID 만 비교(정책 위생). 9차 결정 = FIDO MDS3 **이미지 빌드 고정 판**.
MDS3 BLOB 은 같은 주소가 매달 바뀌어 해시로 고정할 수 없다 → 빌드 때 받은 스냅숏을 FIDO 서명 체인(GlobalSign Root CA - R3 지문 고정·서명자 이름·CRL)으로 검증, 실패 = 빌드 실패.

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| C01 | 단위 회귀 | `make test` | 전부 통과 (test_fido: BLOB 루트 지문·서명자·본문 변조·자체 서명·만료·해시 / packed 체인·none·자기 증명·서명 불일치·AAGUID 확장 불일치·다른 회사 루트·MDS 상태·미등재·OU 요건 / 등록 API 강제·원장 사유 / 허용목록 없이도 유출 보고 기종 거부 / 상태 API) | P0 |
| C02 | 빌드 고정 판 | `docker build --target mds` | MDS3 받기(캐시 7일·실패 시 캐시 사본) → `python -m app.fido verify /opt/fido --crl` = 서명 체인·고정 루트·서명자·CRL 통과, 기종 수·유출/우회 보고 수 | P0 |
| C03 | 빌드 실패 | 고정 지문과 다른 루트·변조 BLOB | 검증 실패 → 빌드 실패 | P0 |
| C04 | 실제 스냅숏 | 이미지 안 `/opt/fido` · `GET /v1/auth/mds` | loaded·번호·다음 갱신·서명자 mds3.fidoalliance.org·YubiKey 5 항목 존재 | P0 |
| C05 | 브라우저 증명 | Playwright 가상 인증기(direct) — 허용목록 테넌트 등록 | 가상 인증기 증명은 MDS 체인 밖 → 422 거부·원장 사유 · 허용목록 없는 테넌트는 등록 성공 | P1 |
