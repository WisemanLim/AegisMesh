# 브라우저 E2E 실행 이미지 (Epic 34·39) — 공식 Playwright 이미지(브라우저·시스템 의존성 포함)에 같은 판의 Python 패키지만 더한다.
FROM mcr.microsoft.com/playwright/python:v1.55.0-noble
RUN pip install --no-cache-dir --break-system-packages playwright==1.55.0
# 접근성 점검 엔진 (Epic 39) — axe-core 공식 npm 배포본, 판 고정
ADD https://registry.npmjs.org/axe-core/-/axe-core-4.10.3.tgz /tmp/axe.tgz
RUN mkdir -p /opt/axe && tar -xzf /tmp/axe.tgz -C /tmp package/axe.min.js && mv /tmp/package/axe.min.js /opt/axe/ && rm -rf /tmp/axe.tgz /tmp/package
