# 시험 결과 / Test Result — impl 20th (Epic 20 헬름 차트·k8s 리허설·단일 파일 CLI)
- 일자: 2026-10-06 · 대상: 로컬 k3d(k3s v1.35.5, 노드 1) + local compose + 무네트워크 debian:bookworm-slim · 커밋: —

## 요약 / Summary
- 전체 7, 통과 7, 실패 0 → 최종 **PASS** (재시도 3회: k3d 이미지 반입, CLI glibc, worker 기동 순서)
- `make test` **292 passed** (+ 사전 점검·worker 대기 2) · `make test-web` 7 + tsc · `make helm-lint` OK · coverage 80/80

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T20-01 | PASS | `helm lint` 0 실패, template 15 리소스(ConfigMap 2·Deployment 4·Job·PVC·Secret·Service 4·StatefulSet). 비밀 미입력 → “secrets.authSecret 필요 — CHANGE_ME 금지”, existingSecret 이면 Secret 미생성 |
| T20-02 | PASS | 로컬 이미지 4종 반입(레지스트리 pull 없음) → 설치 42초, migrate Job 성공, api·web·worker·otel·postgres Running (round 2 worker restarts=0) |
| T20-03 | PASS | health ok · coverage 80/80 · tool 관문 require_approval 14종 1.3ms · 원장 검증 True · sandbox L1(Landlock 8·seccomp 18, k8s RuntimeDefault 안에서도) · 격리 7/7 “역할 aegis_app super=False bypassrls=False · 교차 조회 0건” · OTel http://aegis-otel:4318 |
| T20-04 | PASS | `helm upgrade --reuse-values evidenceRetentionDays=365` → api 롤링 완료 → 반영 365, revision 2 deployed |
| T20-05 | PASS | dist/aegis-linux-arm64 (29MB). 파이썬 없음·glibc 2.36·--network none: list 80 · run d2-03 Finding · eval d1-05 PASS · coverage 80/80 · verify-bundle OK · airgap verify signature·hash·sbom OK · keygen · serve rest 기동 |
| T20-06 | PASS | /install 사전 점검 8/8(DB·마이그레이션 0009=head·키·수집기·L1·worker·관리자·커버리지), /install/helm 값(복제 3·외부 DB·인그레스) → `helm template` 렌더(RWX·Ingress·StatefulSet 없음), compose·cli 콘솔 오류 0 |
| T20-07 | PASS | 292 passed · vitest · tsc · helm-lint · gen_otel_config --check(헬름 사본 포함) |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | `k3d image import` → `content digest … not found` | Docker Desktop containerd 저장소가 다중 아키텍처 인덱스를 통째로 내보냄(로컬에 없는 플랫폼 참조) | 노드 아키텍처만 `docker save --platform` → 노드 `ctr import` | round 2 반입 4/4 |
| 1 | CLI 가 bookworm 에서 `GLIBC_2.38 not found` | python:3.12-slim 이 trixie(glibc 2.41) 기반 | CLI 빌드 스테이지를 python:3.12-slim-bookworm(glibc 2.36)으로 | PASS |
| 1 | k8s worker 파드 Error·재시작 2 | post-install 마이그레이션 Job 보다 먼저 기동 → 표 없음 | worker 가 스키마 준비를 기다림(`wait_for_schema`) + 시험 | round 2 restarts=0 |
| — | 시험 코드: worker 대기 시험 60초 후 실패 | 몽키패치한 함수를 자기 자신에서 다시 호출 | 원본 참조 보관 | 292 passed |

## 설계 결정 기록
- 차트: 비밀은 existingSecret 권장(값 직접 입력 시 CHANGE_ME·빈 값 거부). 마이그레이션·시드 = post-install/upgrade 훅 Job, `--wait-for-jobs`. /app/data(심사 번들·취약점 DB) PVC — api 복제 >1 이면 RWX 필요(NOTES·마법사 안내).
- 파드 보안: runAsNonRoot 10001 · seccomp RuntimeDefault · allowPrivilegeEscalation false · capabilities drop ALL. 이 조건에서도 L1 샌드박스(Landlock·seccomp 중첩) 동작 확인.
- CLI: PyInstaller onefile(리눅스, glibc ≥ 2.36). 에이전트 코드는 동적 적재라 import 를 AST 로 모아 hidden-import. macOS·Windows 바이너리·서명(cosign)은 후속. SBOM 생성은 파이썬 배포판 메타데이터가 필요해 플랫폼 쪽에서 수행.

## 첨부 / Logs
- logs/ (비커밋): k8s-rehearsal(.txt, round2), make-cli, cli-standalone, t20-console, console-values(+rendered), 스크린샷
