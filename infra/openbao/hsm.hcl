# OpenBao HSM 봉인 리허설 (Epic 68) — raft 단일 노드 · PKCS#11 자동 봉인 해제(SoftHSM2) · 상호 TLS. `make bao-hsm-up ENV=prod`
# 사용자 PIN 은 BAO_HSM_PIN(비커밋 infra/openbao/hsm.env). 운영 = 실제 HSM 의 lib·token_label·key_label 로 바꾸고 나머지는 그대로.
ui            = false
disable_mlock = true

storage "raft" {
  path = "/openbao/file"
}

listener "tcp" {
  address                            = "0.0.0.0:8200"
  cluster_address                    = "0.0.0.0:8201"
  tls_cert_file                      = "/tls/tls.crt"
  tls_key_file                       = "/tls/tls.key"
  tls_client_ca_file                 = "/tls/ca.crt"
  tls_require_and_verify_client_cert = true
  tls_min_version                    = "tls13"
}

# SoftHSM2 는 RSA-OAEP 의 해시가 SHA-1 뿐(MGF1 포함) — 실제 HSM 은 rsa_oaep_hash = "sha256" 또는 AES-GCM
seal "pkcs11" {
  lib           = "/usr/lib/softhsm/libsofthsm2.so"
  token_label   = "AegisMesh"
  key_label     = "bao-unseal-rsa"
  mechanism     = "CKM_RSA_PKCS_OAEP"
  rsa_oaep_hash = "sha1"
}
