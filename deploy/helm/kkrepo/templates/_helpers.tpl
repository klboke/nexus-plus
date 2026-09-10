{{- define "kkrepo.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "kkrepo.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "kkrepo.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "kkrepo.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
app.kubernetes.io/name: {{ include "kkrepo.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "kkrepo.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kkrepo.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "kkrepo.scannerSelectorLabels" -}}
app.kubernetes.io/name: {{ printf "%s-scanner" (include "kkrepo.name" .) | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: security-scanner
{{- end }}

{{- define "kkrepo.scannerLabels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{ include "kkrepo.scannerSelectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "kkrepo.scannerUpdaterSelectorLabels" -}}
app.kubernetes.io/name: {{ printf "%s-scanner-db-updater" (include "kkrepo.name" .) | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: security-scanner-db-updater
{{- end }}

{{- define "kkrepo.scannerUpdaterLabels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{ include "kkrepo.scannerUpdaterSelectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "kkrepo.scannerName" -}}
{{- $base := include "kkrepo.fullname" . | trunc 51 | trimSuffix "-" -}}
{{- printf "%s-scanner" $base | trunc 59 | trimSuffix "-" -}}
{{- end }}

{{- define "kkrepo.scannerUpdaterName" -}}
{{- $base := include "kkrepo.fullname" . | trunc 42 | trimSuffix "-" -}}
{{- printf "%s-scanner-db-updater" $base | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "kkrepo.scannerHeadlessName" -}}
{{- $base := include "kkrepo.fullname" . | trunc 46 | trimSuffix "-" -}}
{{- printf "%s-scanner-headless" $base | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "kkrepo.scannerDatabaseClaimName" -}}
{{- $base := include "kkrepo.fullname" . | trunc 52 | trimSuffix "-" -}}
{{- printf "%s-scanner-db" $base | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "kkrepo.scannerBaseUrls" -}}
{{- $root := . -}}
{{- $scannerName := include "kkrepo.scannerName" . -}}
{{- $headlessName := include "kkrepo.scannerHeadlessName" . -}}
{{- range $index, $_ := until (int .Values.securityScanning.replicaCount) -}}
{{- if gt $index 0 }},{{ end -}}
http://{{ $scannerName }}-{{ $index }}.{{ $headlessName }}:{{ $root.Values.securityScanning.service.port }}
{{- end -}}
{{- end }}

{{- define "kkrepo.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "kkrepo.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "kkrepo.validate" -}}
{{- if not (has .Values.database.type (list "mysql" "postgresql")) }}
{{- fail "database.type must be mysql or postgresql" }}
{{- end }}
{{- if not .Values.externalDatabase.enabled }}
{{- fail "externalDatabase.enabled must remain true unless an explicit database subchart is added" }}
{{- end }}
{{- if .Values.embeddedDatabase.enabled }}
{{- fail "embeddedDatabase.enabled is not implemented; use an external database" }}
{{- end }}
{{- if and (gt (int .Values.replicaCount) 1) .Values.blobStorage.file.enabled (not .Values.blobStorage.file.existingClaim) }}
{{- fail "replicaCount > 1 with File storage requires blobStorage.file.existingClaim backed by ReadWriteMany storage" }}
{{- end }}
{{- if and .Values.securityScanning.enabled (not .Values.securityScanning.serviceCredential.existingSecret) }}
{{- fail "securityScanning.serviceCredential.existingSecret is required when scanning is enabled" }}
{{- end }}
{{- if and .Values.securityScanning.enabled .Values.securityScanning.scannerDatabase.caCert.existingSecret (not .Values.securityScanning.scannerDatabase.caCert.key) }}
{{- fail "securityScanning.scannerDatabase.caCert.key is required when a CA Secret is configured" }}
{{- end }}
{{- if and .Values.securityScanning.enabled (lt (int .Values.securityScanning.replicaCount) 1) }}
{{- fail "securityScanning.replicaCount must be at least 1 when scanning is enabled" }}
{{- end }}
{{- if and .Values.securityScanning.enabled (gt (int .Values.securityScanning.replicaCount) 1000) }}
{{- fail "securityScanning.replicaCount must not exceed 1000 so scanner pod DNS labels remain valid" }}
{{- end }}
{{- if and .Values.securityScanning.enabled (not .Values.securityScanning.scannerDatabase.persistence.enabled) }}
{{- fail "security scanning requires scannerDatabase.persistence so the egress-isolated updater can publish the Grype database" }}
{{- end }}
{{- if and .Values.securityScanning.enabled (not .Values.securityScanning.scannerDatabase.autoUpdate) (not .Values.securityScanning.scannerDatabase.persistence.existingClaim) }}
{{- fail "securityScanning.scannerDatabase.autoUpdate=false requires scannerDatabase.persistence.existingClaim pre-populated with an immutable generation layout" }}
{{- end }}
{{- if and .Values.securityScanning.enabled (gt (int .Values.securityScanning.replicaCount) 1) .Values.securityScanning.scannerDatabase.persistence.enabled (not .Values.securityScanning.scannerDatabase.persistence.existingClaim) }}
{{- fail "multiple scanner replicas with persistence require scannerDatabase.persistence.existingClaim backed by ReadWriteMany storage" }}
{{- end }}
{{- if and .Values.securityScanning.enabled .Values.securityScanning.networkPolicy.databaseMirror.enabled (not .Values.securityScanning.networkPolicy.databaseMirror.cidr) }}
{{- fail "securityScanning.networkPolicy.databaseMirror.cidr is required when databaseMirror.enabled=true" }}
{{- end }}
{{- if and .Values.securityScanning.enabled .Values.securityScanning.networkPolicy.databaseMirror.enabled (not .Values.securityScanning.networkPolicy.databaseMirror.port) }}
{{- fail "securityScanning.networkPolicy.databaseMirror.port is required when databaseMirror.enabled=true" }}
{{- end }}
{{- end }}
