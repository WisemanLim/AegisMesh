# OpenBao HSM 봉인 리허설 (Epic 68) — OpenBao HSM 빌드(cgo, PKCS#11 내장) 고정 판 + SoftHSM2(PKCS#11 소프트웨어 HSM)·OpenSC(pkcs11-tool).
# 운영은 같은 설정에서 lib·token_label 만 실제 HSM 의 PKCS#11 모듈로 바꾼다.
FROM openbao/openbao-hsm:2.4.1@sha256:bdba099c4e40bedaf0c4bde38056f71e88244b35e97d2083ffb82ca4747846a6
RUN apk add --no-cache softhsm opensc && mkdir -p /openbao/hsm/tokens && chown -R openbao:openbao /openbao/hsm \
    && softhsm2-util --version && pkcs11-tool --version 2>&1 | head -1
COPY softhsm2.conf /etc/softhsm2.conf
COPY token.sh /hsm/token.sh
