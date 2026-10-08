"""기본 엔진: 이미지·오디오·PDF·오피스 첨부에서 추출한 텍스트·메타데이터의 인젝션 (FR-X06).
params.attachments = [{name, type, extractedText, metadata: {..}, hiddenText}] — 추출은 앞단(OCR·STT·파서)이 수행."""
from aegis.engine import signal
from aegis.patterns import find_directive
from aegis.schemas import JudgeRequest

id = "attachment_scan"


def scan(req: JudgeRequest):
    out = []
    for i, att in enumerate(req.params.get("attachments", [])):
        loc = f"attachments[{i}]:{att.get('name', att.get('type'))}"
        if att.get("extractedText") is None:
            out.append(signal("unscanned", 0.65, "low", loc, f"{att.get('type')} 첨부의 텍스트 추출 결과 없음 — 검사 불가"))
            continue
        if (m := find_directive(att["extractedText"])):
            out.append(signal("embedded-instruction", 0.93, "high", loc, f"{att.get('type')} 내부 텍스트에 지시문", "span", m.start(), m.end() - m.start()))
        for k, v in (att.get("metadata") or {}).items():
            if find_directive(str(v)):
                out.append(signal("metadata-instruction", 0.92, "high", f"{loc}.metadata.{k}", "메타데이터(EXIF·문서 속성)에 지시문"))
        if att.get("hiddenText") and find_directive(str(att["hiddenText"])):
            out.append(signal("hidden-layer", 0.95, "critical", loc, "보이지 않는 텍스트 층(흰 글씨·0pt·숨김 레이어)에 지시문"))
    return out
