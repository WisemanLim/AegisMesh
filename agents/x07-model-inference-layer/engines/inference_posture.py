"""기본 엔진: 추론 서버 상태·산출물 무결성·모델 추출 시도 (FR-X07).
artifact = {kind: inference_server, name, version, auth, public, artifactSha256, expectedSha256, queries: {distinct, total, systematic}}"""
from aegis.engine import artifact_of, signal
from aegis.schemas import JudgeRequest

id = "inference_posture"


def scan(req: JudgeRequest):
    a = artifact_of(req, "inference_server")
    if not a:
        return []
    out = []
    if a.get("public") and not a.get("auth"):
        out.append(signal("open-endpoint", 0.95, "critical", "artifact.auth", "인증 없는 공개 추론 엔드포인트"))
    vuln = req.params.get("vulnerableVersions", {}).get(a.get("name"), [])
    if a.get("version") in vuln:
        out.append(signal("vulnerable-server", 0.93, "critical", "artifact.version", f"취약 버전 {a.get('name')} {a.get('version')}"))
    if a.get("expectedSha256") and a.get("artifactSha256") != a["expectedSha256"]:
        out.append(signal("artifact-mismatch", 0.95, "critical", "artifact.artifactSha256", "양자화·병합 산출물 해시 불일치"))
    q = a.get("queries") or {}
    if q.get("systematic") and q.get("distinct", 0) > req.params.get("extractionQueries", 10000):
        out.append(signal("extraction-pattern", 0.8, "medium", "artifact.queries", f"체계적 질의 {q['distinct']}건 — 모델 추출 의심"))
    return out
