"""D1-06 인젝션 경유 유출 — 고엔트로피 외부 전송은 차단, 비허용 이미지 자동 렌더는 제거(무해화)."""
import re

from aegis.decide import decide

RULES = {
    "D1-06.high-entropy-egress": "출력의 이미지·링크 URL 이 허용목록 밖 호스트로 고엔트로피 파라미터를 보낸다(컨텍스트 반출). 차단.",
    "D1-06.auto-render": "허용목록 밖 호스트의 이미지 자동 렌더. 이미지를 링크 텍스트로 바꿔 무해화.",
    "D1-06.pass": "출력 URL 허용목록·엔트로피 검사 통과.",
}
IMG = re.compile(r"!\[(?P<alt>[^\]]*)\]\([^)]*\)|<img[^>]*>", re.I)


def strip_images(text: str) -> str:
    return IMG.sub(lambda m: f"[이미지 제거됨: {m.group('alt') or '외부 이미지'}]", text)


def detect(req, engine):
    return decide("D1-06", engine.scan(req), {"high-entropy-egress": "block", "auto-render": "transform"}, rules=2,
                  transform=lambda _s: strip_images(req.output or ""))
