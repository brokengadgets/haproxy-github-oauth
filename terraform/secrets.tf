# Secret lifecycle:
#   1. `terraform apply` — creates empty secret containers, then FAILS on the
#      data lookups below (no versions exist yet). This is expected.
#   2. Run the bootstrap script (see scripts/bootstrap-secrets.sh).
#   3. `terraform apply` again — data lookups succeed, VM is provisioned.
#
# Terraform never reads the secret values — only their existence is checked.
# Nothing sensitive is written to tfstate.

resource "google_project_service" "secretmanager" {
  service            = "secretmanager.googleapis.com"
  disable_on_destroy = false
}

locals {
  secret_names = [
    "github-client-id",
    "github-client-secret",
    "jwt-secret",
    "miab-host",
    "miab-user",
    "miab-password",
    "openvpn-client-config",
  ]
}

resource "google_secret_manager_secret" "secrets" {
  for_each  = toset(local.secret_names)
  secret_id = each.value

  replication {
    auto {}
  }

  depends_on = [google_project_service.secretmanager]
}

# Verify a version exists for each secret. Fails on first apply (intentionally)
# until you populate the values with `gcloud secrets versions add`.
data "google_secret_manager_secret_version" "check" {
  for_each = toset(local.secret_names)
  secret   = google_secret_manager_secret.secrets[each.value].secret_id
  version  = "latest"
}

# ── Service account for the HAProxy VM ────────────────────────────────────────

resource "google_service_account" "haproxy" {
  account_id   = "haproxy-vm"
  display_name = "HAProxy VM"
}

resource "google_secret_manager_secret_iam_member" "haproxy_accessor" {
  for_each  = toset(local.secret_names)
  secret_id = google_secret_manager_secret.secrets[each.value].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.haproxy.email}"
}
