"""D9-01 클라우드 오구성 — 공개 버킷·IAM 와일드카드·관리 포트 개방은 차단(배포 거부), 미암호화는 경보."""
from aegis.decide import decide

VM = {"public-bucket": "block", "iam-wildcard": "block", "open-admin-port": "block", "unencrypted": "alert"}
RULES = {f"D9-01.{k}": f"IaC 점검 '{k}' → {v}." for k, v in VM.items()} | {"D9-01.pass": "IaC 정적 검사 통과."}


def detect(req, engine):
    return decide("D9-01", engine.scan(req), VM, rules=len(VM))
