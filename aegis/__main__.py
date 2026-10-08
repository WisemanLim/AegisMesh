import os
import sys

from aegis.cli import main

try:
    sys.exit(main())
except BrokenPipeError:                 # `aegis list | head` — 읽는 쪽이 먼저 닫음. 추적 출력 없이 끝낸다(Python 문서 권장 방식)
    os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    sys.exit(1)
