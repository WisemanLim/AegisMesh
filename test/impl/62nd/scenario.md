# 62nd — TPM·android-key 증명 (Epic 62 · 54 확장)

근거: 54th 는 packed 만 — Windows Hello(TPM 2.0)·Android 키 저장소는 허용목록에 넣어도 형식 때문에 거부됐다. 실물 장치·가상 인증기로 두 형식을 낼 수 없어 합성 PKI 로 시험한다.

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| C01 | 단위 | test_fido | android-key: KeyDescription challenge = clientDataHash · allApplications 거부 · TEE origin 생성·서명 용도 · 증명서 키 = 자격 증명 키 / tpm: pubArea 키 = 자격 증명 키 · certInfo magic·type·extraData = H(authData‖cdh)·name = H(pubArea) · AIK 서명 · AIK 증명서(주체 비움·SAN·EKU 2.23.133.8.3·CA 아님) · ver 2.0 / 둘 다 MDS 체인·AAGUID 확장 | P0 |
| C02 | 근거 | 실제 MDS3 no 290 | 해당 기종(Windows Hello·Android Authenticator 등)이 MDS 에 루트와 함께 있음 | P1 |
| C03 | 회귀 | `make test` · packed·none·자기 증명 | 기존 거부·통과 그대로, 그 밖의 형식(fido-u2f 등)은 attestation_format | P0 |
