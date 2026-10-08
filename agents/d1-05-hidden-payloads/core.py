"""D1-05 은닉 페이로드 — 판정 로직(순수 함수). detect(req, engine) -> Decision."""
import re
import unicodedata

from aegis.decide import decide

RULES = {
    "D1-05.unicode-tag": "유니코드 태그 블록(U+E0000–E007F)으로 숨긴 지시(ASCII smuggling). 차단.",
    "D1-05.zero-width": "제로폭 문자 2개 이상. 정규화·제거 후 통과(무해화).",
    "D1-05.bidi-override": "양방향 제어 문자로 표시 순서를 조작. 정규화·제거 후 통과(무해화).",
    "D1-05.html-comment": "HTML 주석 안에 지시문. 렌더 시 보이지 않는 지시. 차단.",
    "D1-05.hidden-css": "숨김 스타일(display:none·흰 글씨·0 크기) 안에 지시문. 차단.",
    "D1-05.alt-text": "이미지 대체텍스트 안에 지시문. 차단.",
    "D1-05.pass": "6개 규칙 검사 통과.",
}
VERDICT = {"unicode-tag": "block", "html-comment": "block", "hidden-css": "block", "alt-text": "block",
           "zero-width": "transform", "bidi-override": "transform"}
_STRIP = re.compile(r"[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000E0000-\U000E007F]")


def sanitize(text: str) -> str:
    return _STRIP.sub("", unicodedata.normalize("NFKC", text))


def detect(req, engine):
    return decide("D1-05", engine.scan(req), VERDICT, rules=6,
                  transform=lambda _s: sanitize(req.text or ""))
