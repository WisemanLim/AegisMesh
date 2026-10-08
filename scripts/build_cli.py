"""단일 파일 CLI 빌드 (NFR-C1 "단일 바이너리 CLI") — PyInstaller onefile. Dockerfile `cli` 스테이지에서 실행.

에이전트 core·engines 는 파일 경로로 동적 적재되므로 PyInstaller 가 의존 모듈을 못 본다 →
agents/**/*.py 의 import 를 AST 로 모아 hidden-import 로 넘긴다. 에이전트 디렉터리·도식 항목은 데이터로 동봉.
"""
import ast
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def agent_imports() -> list[str]:
    mods: set[str] = set()
    for f in (ROOT / "agents").rglob("*.py"):
        for n in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if isinstance(n, ast.Import):
                mods |= {a.name for a in n.names}
            elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
                mods.add(n.module)
    return sorted(mods)


def main() -> int:
    args = [sys.executable, "-m", "PyInstaller", "--onefile", "--name", "aegis", "--clean", "--noconfirm",
            "--paths", str(ROOT), "--collect-submodules", "aegis", "--hidden-import", "scripts.verify_coverage",
            "--add-data", f"{ROOT / 'agents'}:agents", "--add-data", f"{ROOT / 'diagram_items.json'}:.",
            "--add-data", f"{ROOT / 'scripts' / 'verify_coverage.py'}:scripts",
            "--exclude-module", "app", "--exclude-module", "pytest"]
    for m in agent_imports():
        args += ["--hidden-import", m]
    args.append(str(ROOT / "aegis" / "__main__.py"))
    print("hidden imports:", agent_imports())
    return subprocess.call(args, cwd=ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
