#!/bin/sh
# 외부 복사용 객체 저장 (Epic 52 · NFR-A5) — SeaweedFS 4.48. S3 만 상호 TLS 로 열고(클라이언트 인증서 필수), master·volume·filer 는
# 컨테이너 안(127.0.0.1)에만 묶는다. S3 자격 증명은 환경 변수에서 만들어 /tmp 에 두고 출력하지 않는다. 권한은 백업 버킷 하나로 한정.
set -eu
umask 077
cat > /tmp/s3.json <<JSON
{"identities": [{"name": "backup-ship", "credentials": [{"accessKey": "${S3_ACCESS_KEY}", "secretKey": "${S3_SECRET_KEY}"}],
                 "actions": ["Read:${S3_BUCKET}", "Write:${S3_BUCKET}", "List:${S3_BUCKET}", "Tagging:${S3_BUCKET}", "Admin:${S3_BUCKET}"]}]}
JSON
mkdir -p /etc/seaweedfs && cp /aegis-obj/security.toml /etc/seaweedfs/security.toml   # gRPC 상호 TLS
printf '\n[jwt.filer_signing]\nkey = "%s"\n' "$(head -c 32 /dev/urandom | base64)" >> /etc/seaweedfs/security.toml   # 기동마다 새 내부 서명 키(같은 프로세스 구성요소끼리만)
exec weed server -dir=/data -ip=127.0.0.1 -ip.bind=127.0.0.1 -volume.max=0 -master.volumeSizeLimitMB=1024 \
  -s3 -s3.ip.bind=0.0.0.0 -s3.port=8333 -s3.port.iceberg=0 -s3.port.lance=0 -s3.config=/tmp/s3.json \
  -s3.cert.file=/tls/tls.crt -s3.key.file=/tls/tls.key -s3.cacert.file=/tls/ca.crt -s3.tlsVerifyClientCert
