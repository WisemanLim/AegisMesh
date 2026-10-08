{{- define "aegismesh.fullname" -}}{{- printf "%s" .Release.Name | trunc 50 | trimSuffix "-" -}}{{- end -}}
{{- define "aegismesh.labels" -}}
app.kubernetes.io/name: aegismesh
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "aegismesh.selector" -}}
app.kubernetes.io/name: aegismesh
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "aegismesh.secretName" -}}{{ .Values.secrets.existingSecret | default (printf "%s-secrets" (include "aegismesh.fullname" .)) }}{{- end -}}
{{- define "aegismesh.apiImage" -}}{{ .Values.image.api.repository }}:{{ .Values.image.api.tag }}{{- end -}}
{{- define "aegismesh.dbHost" -}}{{ include "aegismesh.fullname" . }}-postgres{{- end -}}
{{/* API·worker·마이그레이션 공통 환경 */}}
{{- define "aegismesh.env" -}}
- name: DB_PASSWORD
  valueFrom: { secretKeyRef: { name: {{ include "aegismesh.secretName" . }}, key: DB_PASSWORD } }
- name: DATABASE_URL
  {{- if .Values.postgresql.enabled }}
  value: "postgresql+psycopg://{{ .Values.postgresql.user }}:$(DB_PASSWORD)@{{ include "aegismesh.dbHost" . }}:5432/{{ .Values.postgresql.database }}"
  {{- else }}
  value: {{ required "postgresql.enabled=false 이면 externalDatabase.url 필요" .Values.externalDatabase.url | quote }}
  {{- end }}
{{- range $k := list "LEDGER_SIGNING_KEY" "SVID_SIGNING_KEY" "AUTH_SECRET" }}
- name: {{ $k }}
  valueFrom: { secretKeyRef: { name: {{ include "aegismesh.secretName" $ }}, key: {{ $k }} } }
{{- end }}
- name: OIDC_CLIENT_SECRET
  valueFrom: { secretKeyRef: { name: {{ include "aegismesh.secretName" . }}, key: OIDC_CLIENT_SECRET, optional: true } }
{{- end -}}
{{- define "aegismesh.podSecurity" -}}
securityContext: {{- toYaml .Values.podSecurityContext | nindent 2 }}
{{- end -}}
{{- define "aegismesh.containerSecurity" -}}
securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }
{{- end -}}

{{/* 셀렉터(흐름 매핑 한 줄) — (list . "component") */}}
{{- define "aegismesh.sel" -}}{app.kubernetes.io/name: aegismesh, app.kubernetes.io/instance: {{ (index . 0).Release.Name }}, app.kubernetes.io/component: {{ index . 1 }}}{{- end -}}
