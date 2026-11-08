{{- define "agents-vault.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "agents-vault.fullname" -}}
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

{{- define "agents-vault.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "agents-vault.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agents-vault.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "agents-vault.labels" -}}
helm.sh/chart: {{ include "agents-vault.chart" . }}
{{ include "agents-vault.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Call with (dict "context" . "component" "api"). */}}
{{- define "agents-vault.componentLabels" -}}
{{ include "agents-vault.selectorLabels" .context }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "agents-vault.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "agents-vault.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end }}

{{/* imagePullSecrets from values plus global, deduplicated by name. */}}
{{- define "agents-vault.imagePullSecrets" -}}
{{- $g := ((.Values.global | default dict).imagePullSecrets) | default list }}
{{- $seen := dict }}
{{- $all := list }}
{{- range concat (.Values.imagePullSecrets | default list) $g }}
{{- if not (hasKey $seen .name) }}
{{- $_ := set $seen .name true }}
{{- $all = append $all . }}
{{- end }}
{{- end }}
{{- if $all }}
imagePullSecrets:
  {{- toYaml $all | nindent 2 }}
{{- end }}
{{- end }}

{{/* One secretKeyRef block. Call with (dict "ctx" . "existing" name "key" key "own" ownKey "set" bool "what" label).
     Uses the existing Secret when named, else the chart Secret key `own`; fails when neither is set. */}}
{{- define "agents-vault.secretKeyRef" -}}
{{- if and .set .existing -}}
{{- fail (printf "agents-vault: set only one of the %s value and its existing Secret" .what) -}}
{{- else if .existing -}}
name: {{ .existing | quote }}
key: {{ .key | default .own | quote }}
{{- else if .set -}}
name: {{ include "agents-vault.fullname" .ctx | quote }}
key: {{ .own | quote }}
{{- else -}}
{{- fail (printf "agents-vault: the %s is required (set the value or an existing Secret)" .what) -}}
{{- end -}}
{{- end }}

{{- define "agents-vault.databaseRef" -}}
{{- $p := .Values.postgres -}}
{{- if and $p.url $p.existingSecret -}}
{{- fail "agents-vault: set only one of postgres.url and postgres.existingSecret" -}}
{{- end -}}
{{- if not (or $p.url $p.existingSecret) -}}
{{- fail "agents-vault: a Postgres connection is required: set postgres.url or postgres.existingSecret" -}}
{{- end -}}
{{- include "agents-vault.secretKeyRef" (dict "ctx" . "existing" $p.existingSecret "key" $p.existingSecretKey "own" "database-uri" "set" (ne ($p.url | default "") "") "what" "database connection") -}}
{{- end }}

{{- define "agents-vault.orchestratorRef" -}}
{{- $o := .Values.orchestrator -}}
{{- include "agents-vault.secretKeyRef" (dict "ctx" . "existing" $o.existingSecret "key" $o.existingSecretKey "own" "orchestrator-token" "set" (ne ($o.token | default "") "") "what" "orchestrator token") -}}
{{- end }}

{{/* Settings ConfigMap data shared by every component; no secret values. Fails on a bad env key. */}}
{{- define "agents-vault.config" -}}
VAULT_ORCHESTRATOR_URL: {{ required "agents-vault: orchestrator.url is required" .Values.orchestrator.url | quote }}
VAULT_HTTP_PORT: {{ .Values.components.web.port | int | toString | quote }}
VAULT_SERVICE_PORT: {{ .Values.components.service.port | int | toString | quote }}
VAULT_ALLOWED_CIDRS: {{ join "," .Values.allowedCidrs | quote }}
VAULT_NAMESPACE: {{ .Release.Namespace | quote }}
{{- range $k, $v := .Values.env }}
{{- if not (hasPrefix "VAULT_" $k) }}
{{- fail (printf "agents-vault: env key %q must start with VAULT_" $k) }}
{{- end }}
{{ $k }}: {{ $v | toString | quote }}
{{- end }}
{{- end }}

{{/* Container env: the settings ConfigMap and the two secret values. Call with (dict "ctx" . "tokensFile" bool). */}}
{{- define "agents-vault.env" -}}
{{- $ctx := .ctx -}}
envFrom:
  - configMapRef:
      name: {{ include "agents-vault.fullname" $ctx }}-settings
env:
  - name: VAULT_DATABASE_URL
    valueFrom:
      secretKeyRef:
        {{- include "agents-vault.databaseRef" $ctx | nindent 8 }}
  - name: VAULT_ORCHESTRATOR_TOKEN
    valueFrom:
      secretKeyRef:
        {{- include "agents-vault.orchestratorRef" $ctx | nindent 8 }}
  {{- if .tokensFile }}
  - name: VAULT_SERVICE_TOKENS_FILE
    value: /var/run/agents-vault/service-tokens/tokens
  {{- end }}
{{- end }}

{{/* The tokens Secret of the service listener; required. */}}
{{- define "agents-vault.serviceTokensSecret" -}}
{{- required "agents-vault: serviceListener.tokensSecret.name is required" .Values.serviceListener.tokensSecret.name -}}
{{- end }}
