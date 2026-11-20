{{- define "certadillo.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}{{ .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- end -}}

{{- define "certadillo.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "certadillo.selector" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "certadillo.image" -}}
{{- if .Values.image.digest -}}{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}{{ .Values.image.repository }}:{{ .Values.image.tag | default (printf "v%s" .Chart.AppVersion) }}{{- end -}}
{{- end -}}

{{/* Settings shared by the server pods and the migration job. */}}
{{- define "certadillo.env" -}}
- name: CERTADILLO_BASE_URL
  value: {{ .Values.baseUrl | quote }}
- name: CERTADILLO_ORG_NAME
  value: {{ .Values.orgName | quote }}
- name: CERTADILLO_SIGNER
  value: {{ .Values.signer | quote }}
- name: CERTADILLO_DB_URL
  valueFrom: {secretKeyRef: {name: {{ .Values.existingSecret }}, key: {{ .Values.secretKeys.dbUrl }}}}
- name: CERTADILLO_KEY_PASSPHRASE
  valueFrom: {secretKeyRef: {name: {{ .Values.existingSecret }}, key: {{ .Values.secretKeys.keyPassphrase }}}}
{{- if .Values.database.schema }}
- name: CERTADILLO_DB_SCHEMA
  value: {{ .Values.database.schema | quote }}
{{- end }}
{{- if .Values.policies }}
- name: CERTADILLO_POLICY_FILE
  value: /etc/certadillo/policies.yaml
{{- end }}
{{- range $k, $v := .Values.env }}
- name: {{ $k }}
  value: {{ $v | quote }}
{{- end }}
{{- end -}}
