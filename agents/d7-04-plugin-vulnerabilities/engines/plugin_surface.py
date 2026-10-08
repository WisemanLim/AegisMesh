"""기본 엔진: 플러그인 권한 선언·샌드박스·프롬프트 표면 (FR-D7-04).
artifact = {kind: plugin, name, permissionsDeclared, permissions, requestedAtRuntime: [...], sandbox, promptSurfaces: [text]}"""
import re

from aegis.engine import artifact_of, signal
from aegis.schemas import JudgeRequest

id = "plugin_surface"
INJ = re.compile(r"(ignore (all |any )?(previous|prior) instructions|<\s*important\s*>|system\s*:|you (must|are now)|"
                 r"(이전|기존)\s*지시[를을]?\s*무시|지금부터\s*(너는|당신은))", re.I)


def scan(req: JudgeRequest):
    a = artifact_of(req, "plugin")
    if not a:
        return []
    out = []
    if not a.get("permissionsDeclared", False):
        out.append(signal("undeclared-permissions", 0.92, "high", "artifact.permissionsDeclared", "권한 선언 없음"))
    extra = sorted(set(a.get("requestedAtRuntime", [])) - set(a.get("permissions", [])))
    if extra:
        out.append(signal("permission-creep", 0.9, "high", "artifact.requestedAtRuntime", f"선언 밖 런타임 권한 요구 {extra}"))
    if not a.get("sandbox", False):
        out.append(signal("no-sandbox", 0.72, "medium", "artifact.sandbox", "플러그인 샌드박스 없음"))
    for i, t in enumerate(a.get("promptSurfaces", [])):
        if (m := INJ.search(str(t))):
            out.append(signal("prompt-surface-injection", 0.94, "critical", f"artifact.promptSurfaces[{i}]",
                              f"모델에 전달되는 플러그인 문구에 지시문('{m.group(0)[:24]}')"))
    return out
