#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

rendered="$(mktemp)"
disabled_error="$(mktemp)"
preloaded="$(mktemp)"
custom_mirror="$(mktemp)"
invalid_mirror_error="$(mktemp)"

trap 'rm -f "$rendered" "$disabled_error" "$preloaded" "$custom_mirror" "$invalid_mirror_error"' EXIT

helm template security-check "$repository_root/deploy/helm/kkrepo" \
  --set securityScanning.enabled=true \
  --set securityScanning.serviceCredential.existingSecret=kkrepo-scanner \
  >"$rendered"

document_with() {
  local file="$1"
  local needle="$2"

  awk -v needle="$needle" '
    function flush() {
      if (found) {
        for (i = 1; i <= count; i++) print lines[i]
      }
      delete lines
      count = 0
      found = 0
    }

    /^---$/ { flush(); next }

    {
      lines[++count] = $0
      normalized = $0
      sub(/^[[:space:]]+/, "", normalized)
      if (normalized == needle) found = 1
    }

    END { flush() }
  ' "$file"
}

scanner_statefulset="$(document_with "$rendered" "kind: StatefulSet")"
updater_cronjob="$(document_with "$rendered" "kind: CronJob")"
scanner_policy="$(document_with "$rendered" "name: security-check-kkrepo-scanner")"
updater_policy="$(document_with "$rendered" "app.kubernetes.io/component: security-scanner-db-updater")"

grep -A2 -F "name: KKREPO_SCANNER_DB_AUTO_UPDATE" <<<"$scanner_statefulset" \
  | grep -Fq 'value: "false"'

grep -A2 -F "mountPath: /var/lib/kkrepo-scanner/grype" <<<"$scanner_statefulset" \
  | grep -Fq 'readOnly: true'

grep -Fq "KKREPO_SCANNER_DATABASE_UPDATE_ONLY" <<<"$updater_cronjob"

grep -A1 -F "KKREPO_SCANNER_DATABASE_UPDATE_ONLY" <<<"$updater_cronjob" \
  | grep -Fq 'value: "true"'

grep -A1 -F "KKREPO_SCANNER_DATABASE_UPDATE_LOCK_TIMEOUT" <<<"$updater_cronjob" \
  | grep -Fq 'value: "10m"'

if grep -Fq "KKREPO_SCANNER_DB_UPDATE_URL" <<<"$updater_cronjob"; then
  echo "database updater must leave the Grype update URL unset by default" >&2
  exit 1
fi

if grep -Fq "KKREPO_SCANNER_DB_CA_CERT" <<<"$updater_cronjob"; then
  echo "database updater must not configure a CA certificate by default" >&2
  exit 1
fi

if grep -Fq "KKREPO_SCANNER_SERVICE_CREDENTIAL" <<<"$updater_cronjob"; then
  echo "database updater must not receive the scanner service credential" >&2
  exit 1
fi

if grep -A2 -F "mountPath: /var/lib/kkrepo-scanner/grype" <<<"$updater_cronjob" \
  | grep -Fq 'readOnly: true'; then
  echo "database updater requires the only writable database mount" >&2
  exit 1
fi

if grep -Fq "cidr: 0.0.0.0/0" <<<"$scanner_policy"; then
  echo "scan-serving pods must not receive public HTTPS egress" >&2
  exit 1
fi

if grep -Fq "namespaceSelector: {}" "$rendered"; then
  echo "scanner DNS egress must not target every namespace" >&2
  exit 1
fi

for policy in "$scanner_policy" "$updater_policy"; do
  grep -Fq "kubernetes.io/metadata.name: kube-system" <<<"$policy"
  grep -Fq "k8s-app: kube-dns" <<<"$policy"
done

grep -Fq "cidr: 0.0.0.0/0" <<<"$updater_policy"

helm template security-check "$repository_root/deploy/helm/kkrepo" \
  --set securityScanning.enabled=true \
  --set securityScanning.serviceCredential.existingSecret=kkrepo-scanner \
  --set securityScanning.scannerDatabase.updateUrl=https://192.168.1.100/grype-db \
  --set securityScanning.scannerDatabase.caCert.existingSecret=grype-mirror-ca \
  --set securityScanning.scannerDatabase.caCert.key=ca.crt \
  --set securityScanning.networkPolicy.databaseMirror.enabled=true \
  --set securityScanning.networkPolicy.databaseMirror.cidr=192.168.1.100/32 \
  --set securityScanning.networkPolicy.databaseMirror.port=443 \
  >"$custom_mirror"

custom_updater_cronjob="$(document_with "$custom_mirror" "kind: CronJob")"
custom_updater_policy="$(document_with "$custom_mirror" "app.kubernetes.io/component: security-scanner-db-updater")"

grep -A1 -F "name: KKREPO_SCANNER_DB_UPDATE_URL" <<<"$custom_updater_cronjob" \
  | grep -Fq 'value: "https://192.168.1.100/grype-db"'

grep -A1 -F "name: KKREPO_SCANNER_DB_CA_CERT" <<<"$custom_updater_cronjob" \
  | grep -Fq 'value: /etc/kkrepo-ca/ca.crt'

grep -Fq "secretName: grype-mirror-ca" <<<"$custom_updater_cronjob"
grep -Fq "mountPath: /etc/kkrepo-ca" <<<"$custom_updater_cronjob"
grep -Fq "cidr: 192.168.1.100/32" <<<"$custom_updater_policy"

grep -A5 -F "cidr: 192.168.1.100/32" <<<"$custom_updater_policy" \
  | grep -Fq "port: 443"

if helm template security-check "$repository_root/deploy/helm/kkrepo" \
  --set securityScanning.enabled=true \
  --set securityScanning.serviceCredential.existingSecret=kkrepo-scanner \
  --set securityScanning.networkPolicy.databaseMirror.enabled=true \
  >/dev/null 2>"$invalid_mirror_error"; then
  echo "databaseMirror.enabled=true without cidr must fail" >&2
  exit 1
fi

grep -Fq \
  "databaseMirror.cidr is required when databaseMirror.enabled=true" \
  "$invalid_mirror_error"

if helm template security-check "$repository_root/deploy/helm/kkrepo" \
  --set securityScanning.enabled=true \
  --set securityScanning.serviceCredential.existingSecret=kkrepo-scanner \
  --set securityScanning.scannerDatabase.autoUpdate=false \
  >/dev/null 2>"$disabled_error"; then
  echo "disabling automatic database updates without a pre-populated claim must fail" >&2
  exit 1
fi

grep -Fq \
  "autoUpdate=false requires scannerDatabase.persistence.existingClaim pre-populated" \
  "$disabled_error"

helm template security-check "$repository_root/deploy/helm/kkrepo" \
  --set securityScanning.enabled=true \
  --set securityScanning.serviceCredential.existingSecret=kkrepo-scanner \
  --set securityScanning.scannerDatabase.autoUpdate=false \
  --set securityScanning.scannerDatabase.persistence.existingClaim=preloaded-scanner-db \
  >"$preloaded"

if grep -Fq "kind: CronJob" "$preloaded"; then
  echo "automatic database updater must not render when autoUpdate=false" >&2
  exit 1
fi

grep -A2 -F "claimName: preloaded-scanner-db" "$preloaded" >/dev/null

grep -A2 -F "mountPath: /var/lib/kkrepo-scanner/grype" "$preloaded" \
  | grep -Fq "readOnly: true"
