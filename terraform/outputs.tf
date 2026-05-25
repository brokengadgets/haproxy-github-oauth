output "haproxy_external_ip" {
  description = "Static public IP of the HAProxy VM"
  value       = google_compute_address.haproxy.address
}

output "next_steps" {
  value = <<-EOT

    ── Deploy checklist ─────────────────────────────────────────────────────────

    1. First apply (creates secret containers, fails on data lookups — expected):
         terraform apply

    2. Populate secrets (one-time, values never touch tfstate):
         gcloud secrets versions add github-client-id     --data-file=- <<< "..."
         gcloud secrets versions add github-client-secret --data-file=- <<< "..."
         gcloud secrets versions add jwt-secret           --data-file=- <<< "$(openssl rand -hex 32)"
         gcloud secrets versions add miab-host            --data-file=- <<< "box.brokengadgets.io"
         gcloud secrets versions add miab-user            --data-file=- <<< "admin@brokengadgets.io"
         gcloud secrets versions add miab-password        --data-file=- <<< "..."

    3. Second apply (secrets exist, VM is provisioned, DNS records set):
         terraform apply

    4. VPN: copy your OpenVPN client config so HAProxy can reach 10.99.0.2:
         scp client.ovpn debian@${google_compute_address.haproxy.address}:/tmp/
         ssh debian@${google_compute_address.haproxy.address}
         sudo mv /tmp/client.ovpn /etc/openvpn/client/brokengadgets.conf
         sudo systemctl enable --now openvpn-client@brokengadgets
         ping 10.99.0.2   # should succeed

    5. GitHub OAuth App callback URL:
         https://auth.brokengadgets.io/callback

    6. Monitor startup log:
         ssh debian@${google_compute_address.haproxy.address} sudo tail -f /var/log/haproxy-init.log

    ─────────────────────────────────────────────────────────────────────────────
  EOT
}
