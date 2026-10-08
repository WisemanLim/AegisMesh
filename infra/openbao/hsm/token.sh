#!/bin/sh
# SoftHSM2 토큰·봉인 키 준비 (Epic 68) — 있으면 그대로 둔다. 사용자 PIN = BAO_HSM_PIN(비커밋 hsm.env), SO PIN = HSM_SO_PIN(비커밋 hsm-so.pin, 이 단계에만)
# 봉인 키 = RSA-3072 키 쌍(개인 키 민감·추출 불가 — 토큰 밖으로 나오지 않는다), RSA-OAEP. OpenBao 는 키를 만들지 않으므로 여기서 미리 만든다.
# SoftHSM2 는 AES-GCM 에서 IV 를 토큰이 만들지 못해(C_EncryptInit 중단) RSA-OAEP 를 쓴다(68차). 실제 HSM 은 AES-GCM 도 된다.
set -eu
LIB=/usr/lib/softhsm/libsofthsm2.so
P11="pkcs11-tool --module $LIB --token-label AegisMesh --login --pin $BAO_HSM_PIN"
if ! softhsm2-util --show-slots | grep -q "Label:[[:space:]]*AegisMesh"; then
  softhsm2-util --init-token --free --label AegisMesh --pin "$BAO_HSM_PIN" --so-pin "$HSM_SO_PIN" >/dev/null
  echo "토큰 AegisMesh 초기화"
fi
if ! $P11 --list-objects --type privkey 2>/dev/null | grep -q "label:[[:space:]]*bao-unseal-rsa"; then
  $P11 --keypairgen --key-type rsa:3072 --label bao-unseal-rsa --sensitive >/dev/null
  echo "봉인 키 bao-unseal-rsa(RSA-3072) 생성"
fi
$P11 --list-objects --type privkey
