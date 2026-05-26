# The HAProxy VM has a public IP, so no NAT gateway is needed.

resource "google_compute_network" "main" {
  name                    = "brokengadgets-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "main" {
  name          = "main"
  network       = google_compute_network.main.id
  region        = var.region
  ip_cidr_range = "10.10.0.0/24"
}

resource "google_compute_firewall" "allow_http_https" {
  name    = "allow-http-https"
  network = google_compute_network.main.id

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["haproxy"]
}

resource "google_compute_firewall" "allow_ssh" {
  name    = "allow-ssh"
  network = google_compute_network.main.id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  # 35.235.240.0/20 is Google's IAP relay range — required for gcloud ssh --tunnel-through-iap
  source_ranges = concat(var.admin_source_ranges, ["35.235.240.0/20"])
  target_tags   = ["haproxy"]
}

# UDP egress to the OpenVPN server on port 53.
# An explicit egress rule is required so that GCP's stateful firewall tracks
# the UDP flow and automatically permits the server's return packets as ingress.
resource "google_compute_firewall" "allow_openvpn_out" {
  name      = "allow-openvpn-out"
  network   = google_compute_network.main.id
  direction = "EGRESS"

  allow {
    protocol = "udp"
    ports    = [tostring(var.openvpn_port)]
  }
  destination_ranges = ["${var.openvpn_server_ip}/32"]
  target_tags        = ["haproxy"]
}

# Explicit ingress from the VPN server as a belt-and-suspenders complement to
# the stateful tracking above — covers any edge cases where GCP drops the state.
resource "google_compute_firewall" "allow_openvpn_in" {
  name    = "allow-openvpn-in"
  network = google_compute_network.main.id

  allow {
    protocol = "udp"
    ports    = ["1-65535"]
  }
  source_ranges = ["${var.openvpn_server_ip}/32"]
  target_tags   = ["haproxy"]
}
