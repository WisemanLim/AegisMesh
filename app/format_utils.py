"""작은 시간 변환 도우미."""
from datetime import datetime


def iso_to_epoch(s: str) -> float:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
