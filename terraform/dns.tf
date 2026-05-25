# MIAB remains the authoritative DNS for brokengadgets.io — no nameserver change.
# Terraform calls the MIAB REST API (from wherever you run `terraform apply`) to
# set A records for the HAProxy subdomains. Existing MIAB records are untouched.
#
# Credentials are passed via `environment`, NOT stored in triggers — so they are
# never written to tfstate.
#
# NOTE: Terraform's destroy provisioner cannot reference var.* — only self.triggers.
# DNS cleanup on destroy is therefore left as a manual step. The records are harmless
# if left pointing at a released IP (they'll just go unreachable). Remove them via:
#   MIAB admin panel → Custom DNS → delete auth/gitea/pihole/deluge/nextcloud A records
#
# Requires: curl available on the machine running `terraform apply`.

locals {
  haproxy_subdomains = ["auth", "gitea", "nextcloud", "jellyfin", "movies", "frigate"]
}

resource "null_resource" "miab_dns" {
  count = var.manage_miab_dns ? 1 : 0

  # Only non-sensitive values in triggers (triggers ARE stored in tfstate).
  triggers = {
    ip         = google_compute_address.haproxy.address
    subdomains = join(" ", local.haproxy_subdomains)
    domain     = var.domain
    miab_host  = var.miab_host
  }

  provisioner "local-exec" {
    command = <<-EOT
      set -e
      for sub in ${self.triggers.subdomains}; do
        echo "DNS PUT $sub.${self.triggers.domain} -> ${self.triggers.ip}"
        curl -fsSL \
          --user "$MIAB_USER:$MIAB_PASSWORD" \
          -X PUT \
          -d "${self.triggers.ip}" \
          "https://${self.triggers.miab_host}/admin/dns/custom/$sub.${self.triggers.domain}/A"
      done
    EOT
    environment = {
      MIAB_USER     = var.miab_user
      MIAB_PASSWORD = var.miab_password
    }
  }

  depends_on = [google_compute_address.haproxy]
}
