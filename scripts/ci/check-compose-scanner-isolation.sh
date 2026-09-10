#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

for compose_file in \
  "$repository_root/docker-compose.quickstart.yml" \
  "$repository_root/docker-compose.quickstart-postgresql.yml"; do

  rendered="$(mktemp)"
  custom_rendered="$(mktemp)"
  custom_ca="$(mktemp)"
  custom_override="$(mktemp)"

  printf '%s\n' 'test CA certificate' >"$custom_ca"
  printf '%s\n' \
    'services:' \
    '  scanner-database-updater:' \
    '    environment:' \
    '      KKREPO_SCANNER_DB_CA_CERT: /etc/kkrepo-ca/ca.crt' \
    '    volumes:' \
    '      - type: bind' \
    "        source: $custom_ca" \
    '        target: /etc/kkrepo-ca/ca.crt' \
    '        read_only: true' \
    >"$custom_override"

  trap 'rm -f "$rendered" "$custom_rendered" "$custom_ca" "$custom_override"' EXIT

  docker compose \
    -f "$compose_file" \
    --profile security-scanning \
    config \
    --format json >"$rendered"

  python3 - "$compose_file" "$rendered" <<'PY'
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).name

with open(sys.argv[2], encoding="utf-8") as handle:
    model = json.load(handle)

services = model["services"]
scanner = services["scanner"]
updater = services["scanner-database-updater"]
application = services["kkrepo"]
database = services["mysql"] if "mysql" in services else services["postgresql"]

assert scanner["environment"]["KKREPO_SCANNER_DB_AUTO_UPDATE"] == "false", source
assert set(scanner["networks"]) == {"scanner-internal"}, source
assert model["networks"]["scanner-internal"]["internal"] is True, source
assert set(database["networks"]) == {"database-internal"}, source
assert model["networks"]["database-internal"]["internal"] is True, source
assert set(scanner["networks"]).isdisjoint(database["networks"]), source

assert "KKREPO_SCANNER_SERVICE_CREDENTIAL" not in updater["environment"], source
assert updater["environment"]["KKREPO_SCANNER_DATABASE_UPDATE_ONLY"] == "true", source
assert updater["environment"]["KKREPO_SCANNER_DB_AUTO_UPDATE"] == "false", source
assert updater["environment"]["KKREPO_SCANNER_DATABASE_UPDATE_LOCK_TIMEOUT"] == "10m", source
assert updater["environment"]["KKREPO_SCANNER_DB_UPDATE_URL"] == "https://grype.anchore.io/databases", source
assert "KKREPO_SCANNER_DB_CA_CERT" not in updater["environment"], source
assert set(updater["networks"]) == {"scanner-update-egress"}, source
assert "scanner-update-egress" not in application["networks"], source
assert set(application["networks"]) == {
    "database-internal",
    "scanner-internal",
    "application-egress",
}, source

def mounted_volume(service):
    for volume in service["volumes"]:
        if volume["target"] == "/var/lib/kkrepo-scanner/grype":
            return volume
    raise AssertionError(f"{source}: scanner database volume is missing")

scanner_volume = mounted_volume(scanner)
updater_volume = mounted_volume(updater)

assert scanner_volume["source"] == updater_volume["source"], source
assert scanner_volume["read_only"] is True, source
assert updater_volume.get("read_only", False) is False, source
PY

  KKREPO_SCANNER_DB_UPDATE_URL="https://192.168.1.100/grype-db" \
  docker compose \
    -f "$compose_file" \
    -f "$custom_override" \
    --profile security-scanning \
    config \
    --format json >"$custom_rendered"

  python3 - "$compose_file" "$custom_rendered" "$custom_ca" <<'PY'
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).name
ca_file = str(pathlib.Path(sys.argv[3]).resolve())

with open(sys.argv[2], encoding="utf-8") as handle:
    model = json.load(handle)

updater = model["services"]["scanner-database-updater"]

assert updater["environment"]["KKREPO_SCANNER_DB_UPDATE_URL"] == "https://192.168.1.100/grype-db", source
assert updater["environment"]["KKREPO_SCANNER_DB_CA_CERT"] == "/etc/kkrepo-ca/ca.crt", source

ca_volume = next(
    volume for volume in updater["volumes"]
    if volume["target"] == "/etc/kkrepo-ca/ca.crt"
)
assert ca_volume["source"] == ca_file, source
assert ca_volume["read_only"] is True, source
PY

  rm -f "$rendered" "$custom_rendered" "$custom_ca" "$custom_override"
  trap - EXIT

done
