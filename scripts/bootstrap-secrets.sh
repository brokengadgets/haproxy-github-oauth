#!/usr/bin/env bash
# bootstrap-secrets.sh — push secret values to GCP Secret Manager.
#
# Run AFTER the first `terraform apply` creates the empty secret containers,
# then run `terraform apply` again to complete provisioning.
#
# USAGE:
#   cp .env.example .env && $EDITOR .env
#   source .env && ./scripts/bootstrap-secrets.sh
#
# OPENVPN_CONFIG_FILE must be a path to the .ovpn client config file.
# All other secrets are plain strings read from environment variables.

set -euo pipefail

: "${GITHUB_CLIENT_ID:?GITHUB_CLIENT_ID is required}"
: "${GITHUB_CLIENT_SECRET:?GITHUB_CLIENT_SECRET is required}"
: "${JWT_SECRET:?JWT_SECRET is required}"
: "${MIAB_HOST:?MIAB_HOST is required}"
: "${MIAB_USER:?MIAB_USER is required}"
: "${MIAB_PASSWORD:?MIAB_PASSWORD is required}"
: "${OPENVPN_CONFIG_FILE:?OPENVPN_CONFIG_FILE is required (path to .ovpn file)}"

if [ ! -f "$OPENVPN_CONFIG_FILE" ]; then
  echo "ERROR: OPENVPN_CONFIG_FILE not found: $OPENVPN_CONFIG_FILE" >&2
  exit 1
fi

if [ "${#JWT_SECRET}" -lt 32 ]; then
  echo "ERROR: JWT_SECRET must be at least 32 characters. Generate: openssl rand -hex 32" >&2
  exit 1
fi

PROJECT=$(gcloud config get-value project 2>/dev/null)
if [ -z "$PROJECT" ]; then
  echo "ERROR: no active gcloud project. Run: gcloud config set project YOUR_PROJECT_ID" >&2
  exit 1
fi

log() { echo "[INFO]  $*"; }

put_secret_value() {
  local name="$1"
  local value="$2"
  printf '%s' "$value" \
    | gcloud secrets versions add "$name" --project="$PROJECT" --data-file=-
  log "Populated: $name"
}

put_secret_file() {
  local name="$1"
  local file="$2"
  gcloud secrets versions add "$name" --project="$PROJECT" --data-file="$file"
  log "Populated: $name (from $file)"
}

log "Pushing secrets to project: $PROJECT"
echo ""

put_secret_value "github-client-id"     "$GITHUB_CLIENT_ID"
put_secret_value "github-client-secret" "$GITHUB_CLIENT_SECRET"
put_secret_value "jwt-secret"           "$JWT_SECRET"
put_secret_value "miab-host"            "$MIAB_HOST"
put_secret_value "miab-user"            "$MIAB_USER"
put_secret_value "miab-password"        "$MIAB_PASSWORD"
put_secret_file  "openvpn-client-config" "$OPENVPN_CONFIG_FILE"

echo ""
log "All secrets populated. Run: terraform apply"
