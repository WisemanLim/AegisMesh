# OpenBao 운영 마감 리허설 (Epic 56) — 3노드 raft 통합 저장소 · transit 자동 봉인 해제 · 상호 TLS. `make bao-cluster-up ENV=prod`
# 노드마다 같은 설정을 쓰고 이름만 환경 변수로 준다(BAO_RAFT_NODE_ID·BAO_API_ADDR·BAO_CLUSTER_ADDR). 인증서 = 볼륨 tls 의 노드별 하위 경로(/tls).
ui            = false
disable_mlock = true

storage "raft" {
  path = "/openbao/file"
  retry_join {                                    # 처음 기동·재가입 — 누가 리더든 상호 TLS 로 붙는다
    leader_api_addr         = "https://bao-1:8200"
    leader_ca_cert_file     = "/tls/ca.crt"
    leader_client_cert_file = "/tls/tls.crt"
    leader_client_key_file  = "/tls/tls.key"
  }
  retry_join {
    leader_api_addr         = "https://bao-2:8200"
    leader_ca_cert_file     = "/tls/ca.crt"
    leader_client_cert_file = "/tls/tls.crt"
    leader_client_key_file  = "/tls/tls.key"
  }
  retry_join {
    leader_api_addr         = "https://bao-3:8200"
    leader_ca_cert_file     = "/tls/ca.crt"
    leader_client_cert_file = "/tls/tls.crt"
    leader_client_key_file  = "/tls/tls.key"
  }
}

listener "tcp" {
  address                            = "0.0.0.0:8200"
  cluster_address                    = "0.0.0.0:8201"
  tls_cert_file                      = "/tls/tls.crt"
  tls_key_file                       = "/tls/tls.key"
  tls_client_ca_file                 = "/tls/ca.crt"
  tls_require_and_verify_client_cert = true          # 내부 CA 인증서 없는 접속은 TLS 단계에서 거부
  tls_min_version                    = "tls13"
}

# 자동 봉인 해제 — 봉인 해제기(bao-unsealer)의 transit 키로 마스터 키를 포장. 토큰은 BAO_TOKEN(비커밋 infra/openbao/cluster.env, 포장·해제 전용 정책)
# 운영은 클라우드 KMS·HSM(PKCS#11) 또는 별도 사이트의 봉인 해제기를 쓴다.
seal "transit" {
  address         = "https://bao-unsealer:8200"
  mount_path      = "transit/"
  key_name        = "aegis-autounseal"
  tls_ca_cert     = "/tls/ca.crt"
  tls_client_cert = "/tls/tls.crt"
  tls_client_key  = "/tls/tls.key"
}

audit "file" "file" {
  description = "AegisMesh 임대 감사 (Epic 56)"
  options {
    file_path = "/openbao/logs/audit.log"
  }
}
