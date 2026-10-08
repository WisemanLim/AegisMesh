# ExtMCP 정책 서버 (Epic 67) — agentgateway 의 MCP 가드레일(gRPC ExtMcp)을 AegisMesh 관문 판정으로 잇는다.
# 프로토콜 정의는 agentgateway v1.6.0 고정 판(sha256 검증) — 빌드 때 코드 생성, 실행 중 네트워크는 api 만
FROM python:3.12-slim
RUN pip install --no-cache-dir grpcio==1.75.1 grpcio-tools==1.75.1 protobuf==6.32.1
WORKDIR /opt/extmcp
ADD --checksum=sha256:4ba750cca44e9ba68de2ad04e6d507b67f44b1728f09840b78d9e32f3f563584 \
    https://raw.githubusercontent.com/agentgateway/agentgateway/v1.6.0/crates/protos/proto/ext_mcp.proto ./ext_mcp.proto
RUN python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. ext_mcp.proto && pip uninstall -y grpcio-tools
COPY server.py ./
RUN useradd -r -u 10001 app
USER app
EXPOSE 9001
CMD ["python", "server.py"]
