"""기본 엔진: 모델 가중치 파일 — 안전 직렬화 형식 강제, 역직렬화 위험 opcode/전역, 해시·서명 (FR-D7-06).
artifact = {kind: model, name, format, sha256, expectedSha256, signed, signatureValid, pickleGlobals: ["os.system", …]}"""
from aegis.engine import artifact_of, signal
from aegis.schemas import JudgeRequest

id = "model_artifact"
UNSAFE_FORMATS = {"pickle", "pkl", "pt", "pth", "bin", "joblib", "ckpt"}
DANGEROUS = ("os.system", "os.popen", "subprocess", "builtins.exec", "builtins.eval", "posix.system", "nt.system",
             "socket", "runpy", "webbrowser", "pty.spawn", "__builtin__.eval", "shutil.rmtree")


def scan(req: JudgeRequest):
    a = artifact_of(req, "model")
    if not a:
        return []
    out = []
    bad = [g for g in a.get("pickleGlobals", []) if any(g.startswith(d) for d in DANGEROUS)]
    if bad:
        out.append(signal("dangerous-deserialization", 0.98, "critical", "artifact.pickleGlobals", f"역직렬화 시 실행되는 전역 {bad}"))
    if str(a.get("format", "")).lower() in UNSAFE_FORMATS and not req.params.get("allowPickle"):
        out.append(signal("unsafe-format", 0.85, "high", "artifact.format", f"안전하지 않은 직렬화 형식 {a['format']} — safetensors·gguf 강제"))
    if a.get("expectedSha256") and a.get("sha256") != a["expectedSha256"]:
        out.append(signal("hash-mismatch", 0.96, "critical", "artifact.sha256", "가중치 해시가 기대값과 다르다(변조)"))
    if a.get("signed") is False:
        out.append(signal("unsigned", 0.72, "medium", "artifact.signed", "모델 서명 없음"))
    elif a.get("signatureValid") is False:
        out.append(signal("bad-signature", 0.97, "critical", "artifact.signatureValid", "모델 서명 검증 실패"))
    return out
