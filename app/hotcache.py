"""인라인 판정 경로의 읽기 위주 조회 캐시 (NFR-P1) — 짧은 TTL + 이 프로세스의 관련 쓰기 커밋 시 즉시 무효화.

대상: 프로파일 적용·에이전트 행·정책 사양·프로파일 재정의. 다른 프로세스·노드의 변경은 TTL(기본 2초) 안에 반영된다
(NFR-O4 정책 반영 10초 이내). 값은 세션에서 떼어 낸(expunge) 읽기 전용 스냅샷 — 호출자는 고치지 않는다.
키에는 테넌트가 들어가므로 다른 테넌트 값이 섞이지 않는다(FR-P13).
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

from sqlalchemy import event
from sqlalchemy.orm import Session

from app import models
from app.core.config import settings

WATCH = (models.Policy, models.Profile, models.ProfileApplication, models.Agent, models.Tenant)
_data: dict[Any, tuple[int, float, Any]] = {}
_lock = threading.Lock()
_gen = 0
STATS = {"hits": 0, "misses": 0, "invalidations": 0}


def get(key: Any, loader: Callable[[], Any]) -> Any:
    ttl = settings.hot_cache_ttl_sec
    if ttl <= 0:
        return loader()
    now = time.monotonic()
    hit = _data.get(key)
    if hit and hit[0] == _gen and now - hit[1] < ttl:
        STATS["hits"] += 1
        return hit[2]
    gen = _gen                                         # 적재 중 무효화되면 다음 조회에서 다시 읽는다
    val = loader()
    with _lock:
        _data[key] = (gen, now, val)
        STATS["misses"] += 1
    return val


def detach(s: Session, obj: Any) -> Any:
    if obj is not None and obj in s:
        s.expunge(obj)
    return obj


def invalidate() -> None:
    global _gen
    with _lock:
        _gen += 1
        _data.clear()
        STATS["invalidations"] += 1


@event.listens_for(Session, "after_flush")
def _flushed(session: Session, _ctx) -> None:
    if any(isinstance(o, WATCH) for o in (*session.new, *session.dirty, *session.deleted)):
        session.info["hotcache_dirty"] = True


@event.listens_for(Session, "do_orm_execute")
def _bulk(state) -> None:
    if (state.is_update or state.is_delete) and state.bind_mapper is not None and state.bind_mapper.class_ in WATCH:
        state.session.info["hotcache_dirty"] = True


@event.listens_for(Session, "after_commit")
def _committed(session: Session) -> None:
    if session.info.pop("hotcache_dirty", False):
        invalidate()
