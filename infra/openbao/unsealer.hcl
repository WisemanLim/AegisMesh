# 봉인 해제기 (Epic 56) — 3노드 클러스터의 자동 봉인 해제용 transit 키(aegis-autounseal)만 둔다. 자신은 Shamir(키 3개·임계 2) 수동 봉인 해제
# (비커밋 infra/openbao/unsealer-init.json — 운영은 키 보관자 분리·별도 사이트). 상호 TLS 필수.
ui            = false
disable_mlock = true
api_addr      = "https://bao-unsealer:8200"
cluster_addr  = "https://bao-unsealer:8201"

storage "raft" {
  path    = "/openbao/file"
  node_id = "unsealer"
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
