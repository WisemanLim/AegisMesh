"""L1 격리 하위 프로세스 (FR-P08, NFR-I) — 먼저 잠그고(Landlock·seccomp·감사 훅), 그다음 에이전트 코드를 읽는다.

  python -m app.sandbox_child serve <agent_dir>   # 상주: stdin JSON 줄(판정 요청) → stdout JSON 줄(Decision)
  python -m app.sandbox_child replay <agent_dir>  # 등록 심사 R4: 골든·공격 재생 → JSON 요약 1줄
  python -m app.sandbox_child probe               # 탈출 시도 점검 → JSON 1줄
  python -m app.sandbox_child caps                # 커널이 제공하는 잠금 수단 → JSON 1줄
  python -m app.sandbox_child l2probe <marker>    # L2(gVisor) 경계 점검 — 잠금 층 없이 → JSON 1줄 (Epic 65, 브로커가 실행)

잠금 층 (부모가 rlimit·빈 환경·임시 작업 디렉터리를 먼저 건다):
  1) Landlock — 파일 시스템: 읽기 = 런타임·에이전트 디렉터리, 쓰기 = 임시 디렉터리만 (/app/data·키·DB 접근 불가)
  2) seccomp-BPF — 소켓 생성·연결, execve, fork(스레드 제외 clone), ptrace, mount·unshare·setns·chroot 차단
  3) 감사 훅 — 위와 같은 행위를 파이썬 수준에서 한 번 더 차단 + 잠금 후 ctypes 금지
"""
from __future__ import annotations

import ctypes
import json
import os
import platform
import sys

RO_PATHS = ["/usr", "/lib", "/lib64", "/opt/venv", "/etc", "/app/aegis", "/app/app"]
SYSCALL_NR = {
    "x86_64": {"arch": 0xC000003E, "landlock": (444, 445, 446), "clone": 56, "clone3": 435,
               "block": {"socket": 41, "socketpair": 53, "connect": 42, "bind": 49, "listen": 50, "accept": 43, "accept4": 288,
                         "execve": 59, "execveat": 322, "fork": 57, "vfork": 58, "ptrace": 101, "mount": 165, "umount2": 166,
                         "unshare": 272, "setns": 308, "pivot_root": 155, "chroot": 161}},
    "aarch64": {"arch": 0xC00000B7, "landlock": (444, 445, 446), "clone": 220, "clone3": 435,
                "block": {"socket": 198, "socketpair": 199, "bind": 200, "listen": 201, "accept": 202, "connect": 203,
                          "accept4": 242, "execve": 221, "execveat": 281, "ptrace": 117, "mount": 40, "umount2": 39,
                          "unshare": 97, "setns": 268, "pivot_root": 41, "chroot": 51}},
}
_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long


def _arch() -> dict | None:
    m = platform.machine()
    return SYSCALL_NR.get({"arm64": "aarch64", "amd64": "x86_64"}.get(m, m))


# ── Landlock ────────────────────────────────────────────────
class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _PathBeneath(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


FS_ALL = (1 << 13) - 1                      # ABI 1 권한 전부
FS_READ = (1 << 0) | (1 << 2) | (1 << 3)    # EXECUTE · READ_FILE · READ_DIR
FS_FILE = (1 << 0) | (1 << 1) | (1 << 2)    # 파일에 줄 수 있는 권한


def landlock_abi() -> int:
    a = _arch()
    if not a:
        return 0
    v = _libc.syscall(a["landlock"][0], None, ctypes.c_size_t(0), ctypes.c_uint32(1))   # LANDLOCK_CREATE_RULESET_VERSION
    return int(v) if v > 0 else 0


def landlock(read_paths: list[str], write_paths: list[str]) -> int:
    abi = landlock_abi()
    if not abi:
        return 0
    create, add, restrict = _arch()["landlock"]
    attr = _RulesetAttr(FS_ALL)
    rfd = _libc.syscall(create, ctypes.byref(attr), ctypes.c_size_t(ctypes.sizeof(attr)), ctypes.c_uint32(0))
    if rfd < 0:
        return 0
    for p, access in [(p, FS_READ) for p in read_paths] + [(p, FS_ALL) for p in write_paths]:
        if not os.path.exists(p):
            continue
        fd = os.open(p, os.O_PATH | os.O_CLOEXEC)
        allowed = access if os.path.isdir(p) else access & FS_FILE
        rule = _PathBeneath(allowed, fd)
        _libc.syscall(add, ctypes.c_int(rfd), ctypes.c_int(1), ctypes.byref(rule), ctypes.c_uint32(0))
        os.close(fd)
    if _libc.prctl(38, 1, 0, 0, 0) != 0:              # PR_SET_NO_NEW_PRIVS
        return 0
    ok = _libc.syscall(restrict, ctypes.c_int(rfd), ctypes.c_uint32(0)) == 0
    os.close(rfd)
    return abi if ok else 0


# ── seccomp-BPF ─────────────────────────────────────────────
class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8), ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(_SockFilter))]


LD, JEQ, JSET, RET = 0x20, 0x15, 0x45, 0x06
ALLOW, ERRNO, KILL = 0x7FFF0000, 0x00050000, 0x80000000
EPERM, ENOSYS, CLONE_THREAD = 1, 38, 0x00010000


def seccomp() -> list[str]:
    a = _arch()
    if not a:
        return []
    prog = [(LD, 0, 0, 4), (JEQ, 1, 0, a["arch"]), (RET, 0, 0, KILL), (LD, 0, 0, 0)]
    for nr in a["block"].values():
        prog += [(JEQ, 0, 1, nr), (RET, 0, 0, ERRNO | EPERM)]
    prog += [(JEQ, 0, 1, a["clone3"]), (RET, 0, 0, ERRNO | ENOSYS),       # glibc 가 clone 으로 대체
             (JEQ, 0, 3, a["clone"]), (LD, 0, 0, 16), (JSET, 1, 0, CLONE_THREAD), (RET, 0, 0, ERRNO | EPERM),
             (RET, 0, 0, ALLOW)]
    arr = (_SockFilter * len(prog))(*[_SockFilter(*x) for x in prog])
    fprog = _SockFprog(len(prog), arr)
    if _libc.prctl(38, 1, 0, 0, 0) != 0 or _libc.prctl(22, 2, ctypes.byref(fprog), 0, 0) != 0:
        return []
    return sorted(a["block"]) + ["fork(clone without CLONE_THREAD)", "clone3"]


# ── 감사 훅 ─────────────────────────────────────────────────
DENY_EVENTS = ("socket.__new__", "socket.connect", "socket.bind", "socket.getaddrinfo", "subprocess.Popen", "os.system",
               "os.exec", "os.posix_spawn", "os.fork", "os.forkpty", "os.kill", "ctypes.dlopen", "ctypes.dlsym",
               "ctypes.call_function", "ctypes.cdata")


def audit_hook(read_paths: list[str], write_paths: list[str]) -> None:
    lv = os.environ.get("AEGIS_RUNTIME_ISOLATION", "L1")
    rd = tuple(os.path.realpath(p) for p in read_paths + write_paths)
    wr = tuple(os.path.realpath(p) for p in write_paths) + ("/dev/null",)

    def hook(event: str, args: tuple) -> None:
        if event in DENY_EVENTS:
            raise PermissionError(f"sandbox {lv}: {event} 차단")
        if event == "open" and args and isinstance(args[0], (str, bytes)):
            path = os.path.realpath(os.fsdecode(args[0]))
            mode, flags = (args[1] or "r"), (args[2] or 0)
            writing = any(c in str(mode) for c in "wax+") or flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
            if writing and not path.startswith(wr):
                raise PermissionError(f"sandbox {lv}: 쓰기 차단 {path}")
            if not path.startswith(rd) and not path.startswith("/dev/"):
                raise PermissionError(f"sandbox {lv}: 읽기 차단 {path}")
    sys.addaudithook(hook)


def lockdown(extra_read: list[str], tmp: str) -> dict:
    reads = RO_PATHS + extra_read
    abi = landlock(reads, [tmp, "/dev/null"])
    blocked = seccomp()
    audit_hook(reads, [tmp])
    return {"landlock": abi, "seccomp": blocked, "auditHook": True, "tmp": tmp, "machine": platform.machine(),
            "kernel": platform.release()}


def _emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


# ── 모드 ─────────────────────────────────────────────────────
def serve(agent_dir: str, tmp: str) -> None:
    from aegis.agent import load_agent
    from aegis.schemas import JudgeRequest
    caps = lockdown([agent_dir], tmp)
    agent = load_agent(agent_dir)                     # 잠금 후 에이전트 코드 적재
    _emit({"ready": True, "agent": agent.id, "caps": caps})
    for line in sys.stdin:
        try:
            msg = json.loads(line)
            req = JudgeRequest.model_validate(msg["req"])
            eng = agent.engines[msg.get("engine") or agent.manifest.spec.engines.default]
            d = agent.detect(req, eng)
            _emit({"decision": d.model_dump(by_alias=True, mode="json")})
        except Exception as exc:  # noqa: BLE001 — 부모가 failMode 로 강등
            _emit({"error": f"{type(exc).__name__}: {exc}"[:300]})


def replay(agent_dir: str, tmp: str) -> None:
    from aegis.agent import load_agent
    from aegis.harness import evaluate
    caps = lockdown([agent_dir], tmp)
    rep = evaluate(load_agent(agent_dir), repeat=3)
    s = rep.summary()
    _emit({k: s[k] for k in ("golden", "attacks", "fpRate", "detectionRate", "p95Ms", "nondeterministic", "invalid")} | {"caps": caps})


def probe(tmp: str) -> None:
    """탈출 시도 — 각 행위가 막혔는지와 막은 층을 기록한다. 커널 층(seccomp·Landlock)은 감사 훅 설치 전에 따로 확인한다."""
    import errno
    reads = RO_PATHS
    abi = landlock(reads, [tmp, "/dev/null"])
    blocked = seccomp()
    out = []
    raw_sock = _libc.socket(2, 1, 0)                  # 감사 훅을 거치지 않는 libc 직접 호출
    out.append({"test": "libc socket(AF_INET) 직접 호출", "blocked": raw_sock < 0, "layer": "seccomp",
                "detail": errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno())) if raw_sock < 0 else f"fd {raw_sock}"})
    raw_fd = _libc.open(b"/app/data/app.db", 0)
    out.append({"test": "libc open(/app/data/app.db) 직접 호출", "blocked": raw_fd < 0, "layer": "landlock",
                "detail": errno.errorcode.get(ctypes.get_errno(), "") if raw_fd < 0 else "읽힘"})
    audit_hook(reads, [tmp])

    def attempt(name: str, layer: str, fn):
        try:
            r = fn()
            out.append({"test": name, "blocked": False, "layer": layer, "detail": str(r)[:80]})
        except (OSError, PermissionError, MemoryError, RuntimeError) as exc:
            out.append({"test": name, "blocked": True, "layer": layer, "detail": f"{type(exc).__name__}: {exc}"[:120]})

    import socket
    import subprocess
    attempt("socket.create_connection 외부 연결", "audit·seccomp", lambda: socket.create_connection(("1.1.1.1", 443), timeout=1))
    attempt("subprocess 실행 (/bin/sh)", "audit·seccomp", lambda: subprocess.run(["/bin/sh", "-c", "id"], capture_output=True))
    attempt("os.fork", "audit·seccomp", os.fork)
    attempt("/app/data 쓰기", "landlock·audit", lambda: open("/app/data/escape.txt", "w").write("x"))
    attempt("원장 서명 키 읽기", "landlock·audit", lambda: open("/app/data/ledger_ed25519.key", "rb").read(4))
    attempt("/etc/passwd 덮어쓰기", "landlock·audit", lambda: open("/etc/passwd", "a").write("x"))
    attempt("메모리 2GB 할당", "rlimit", lambda: len(bytearray(2 << 30)))
    attempt("환경 변수의 비밀", "env", lambda: (_ for _ in ()).throw(PermissionError("빈 환경")) if not os.environ.get("DATABASE_URL") else os.environ["DATABASE_URL"])
    ok_tmp = True
    try:
        with open(os.path.join(tmp, "ok.txt"), "w") as f:
            f.write("ok")
    except OSError:
        ok_tmp = False
    _emit({"results": out, "control": {"tmpWrite": ok_tmp}, "caps": {"landlock": abi, "seccomp": blocked, "auditHook": True,
                                                                        "machine": platform.machine(), "kernel": platform.release()}})


def caps(tmp: str) -> None:
    _emit(lockdown([], tmp))


def l2probe(marker: str) -> None:
    """L2 경계 — 잠금 층을 걸지 않고 gVisor 자체가 막는지 본다(안쪽 잠금 층은 probe 가 따로). 덧씌움 쓰기 잔존은 브로커가 밖에서."""
    import socket
    out = []
    kernel = platform.release()
    out.append({"test": "커널 = gVisor Sentry(호스트 커널 아님)", "blocked": "gvisor" in kernel, "layer": "gVisor", "detail": kernel})
    for host, port in (("api", 8000), ("db", 5432), ("1.1.1.1", 443)):
        try:
            socket.create_connection((host, port), timeout=2).close()
            out.append({"test": f"네트워크 {host}:{port}", "blocked": False, "layer": "gVisor network=none", "detail": "연결됨"})
        except OSError as exc:
            out.append({"test": f"네트워크 {host}:{port}", "blocked": True, "layer": "gVisor network=none", "detail": f"{type(exc).__name__}: {exc}"[:100]})
    for p in ("/tls", "/registry", "/opt/l2/broker.py", "/var/run/docker.sock", "/dev/kvm", "/app/data/ledger_ed25519.key"):
        out.append({"test": f"샌드박스 밖 파일 {p}", "blocked": not os.path.exists(p), "layer": "gVisor 루트 FS", "detail": "없음" if not os.path.exists(p) else "보임"})
    procs = []
    for d in os.listdir("/proc"):
        if d.isdigit():
            try:
                procs.append(open(f"/proc/{d}/cmdline", "rb").read().replace(b"\0", b" ").decode(errors="replace"))
            except OSError:
                pass
    out.append({"test": "브로커·호스트 프로세스 보기(/proc)", "blocked": not any("broker" in c or "runsc" in c for c in procs),
                "layer": "gVisor PID 이름공간", "detail": f"보이는 프로세스 {len(procs)}"})
    out.append({"test": "환경 변수의 비밀", "blocked": not any(k in os.environ for k in ("DATABASE_URL", "AUTH_SECRET_FILE", "TLS_DIR")),
                "layer": "브로커 빈 환경", "detail": ",".join(sorted(os.environ))[:100]})
    try:
        with open(marker, "w") as f:
            f.write("x")
        wrote = True
    except OSError:
        wrote = False
    _emit({"results": out, "kernel": kernel, "wroteInside": wrote})


def _self_limits() -> None:
    """L2 — 브로커가 runsc 에 rlimit 을 걸 수 없어(Go 런타임) 샌드박스 안 프로세스가 스스로 건다. 높일 수 없다."""
    import resource
    cpu = int(os.environ.get("SANDBOX_CPU_SEC", "60"))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 2**20, 768 * 2**20))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 2**20, 16 * 2**20))


if __name__ == "__main__":
    mode = sys.argv[1]
    tmpdir = os.environ.get("SANDBOX_TMP") or os.getcwd()
    if os.environ.get("SANDBOX_SELF_RLIMIT") and mode != "l2probe":
        _self_limits()
    {"serve": lambda: serve(sys.argv[2], tmpdir), "replay": lambda: replay(sys.argv[2], tmpdir),
     "probe": lambda: probe(tmpdir), "caps": lambda: caps(tmpdir), "l2probe": lambda: l2probe(sys.argv[2])}[mode]()
