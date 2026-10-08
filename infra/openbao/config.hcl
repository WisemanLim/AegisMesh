# OpenBao 운영형 리허설 (Epic 46) — raft 통합 저장소 · 봉인 해제는 수동(키 3개 중 2개, 비커밋 infra/openbao/init.json) · 감사 장치는 bao_setup.py 가 켠다.
# 로컬 리허설이라 TLS 를 끈다. 운영은 TLS 인증서·자동 봉인 해제(KMS/transit)·다중 노드 raft 를 쓴다.
ui            = false
disable_mlock = true
api_addr      = "http://bao-server:8200"
cluster_addr  = "http://bao-server:8201"

storage "raft" {
  path    = "/openbao/file"
  node_id = "bao-1"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

# 감사 장치 — OpenBao 2.4 는 API 로 켜지 않고 설정으로만 선언한다. 토큰·비밀 값은 HMAC 으로 남는다.
audit "file" "file" {
  description = "AegisMesh 임대 감사 (Epic 46)"
  options {
    file_path = "/openbao/logs/audit.log"
  }
}
