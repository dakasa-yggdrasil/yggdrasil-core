{{/*
Expand the name of the chart.
*/}}
{{- define "yggdrasil-core.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "yggdrasil-core.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "yggdrasil-core.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "yggdrasil-core.labels" -}}
helm.sh/chart: {{ include "yggdrasil-core.chart" . }}
{{ include "yggdrasil-core.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "yggdrasil-core.selectorLabels" -}}
app.kubernetes.io/name: {{ include "yggdrasil-core.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "yggdrasil-core.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "yggdrasil-core.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Compose the Postgres host the pod should talk to. When the bitnami
subchart is enabled, follow its service naming convention. Otherwise
fall back to external.postgres.host.
*/}}
{{- define "yggdrasil-core.postgresHost" -}}
{{- if .Values.postgresql.enabled -}}
{{ printf "%s-postgresql" .Release.Name }}
{{- else -}}
{{ .Values.external.postgres.host }}
{{- end -}}
{{- end }}

{{- define "yggdrasil-core.rabbitmqHost" -}}
{{- if .Values.rabbitmq.enabled -}}
{{ printf "%s-rabbitmq" .Release.Name }}
{{- else -}}
{{ .Values.external.rabbitmq.url }}
{{- end -}}
{{- end }}

{{/*
Name of the Secret holding bootstrap + DB + AMQP credentials.
*/}}
{{- define "yggdrasil-core.secretName" -}}
{{ printf "%s-secrets" (include "yggdrasil-core.fullname" .) }}
{{- end }}
