"""D3-03 시스템 장악 — 민감 경로·권한 상승 명령·지속성·다운로드 실행·리버스 셸·컨테이너 탈출. 무조건 차단."""
from aegis.decide import decide

KINDS = {"sensitive-path": "민감 시스템 경로 접근", "privilege-cmd": "권한 명령(sudo·chmod 777·setuid)",
         "persistence": "지속성 확보(cron·서비스·셸 프로파일·authorized_keys)", "download-exec": "다운로드 후 즉시 실행",
         "reverse-shell": "리버스 셸", "container-escape": "컨테이너 탈출 시도"}
RULES = {f"D3-03.{k}": f"도구 인자에 {v}. 차단(승인으로도 해제 불가)." for k, v in KINDS.items()}
RULES["D3-03.pass"] = "시스템 장악 지표 미검출."


def detect(req, engine):
    return decide("D3-03", engine.scan(req), {k: "block" for k in KINDS}, rules=len(KINDS))
