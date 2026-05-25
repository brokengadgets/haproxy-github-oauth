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
  source_ranges = var.admin_source_ranges
  target_tags   = ["haproxy"]
}

# UDP 1194 outbound for the OpenVPN tunnel to the existing VPN gateway.
resource "google_compute_firewall" "allow_openvpn_out" {
  name      = "allow-openvpn-out"
  network   = google_compute_network.main.id
  direction = "EGRESS"

  allow {
    protocol = "udp"
    ports    = ["1194"]
  }
  destination_ranges = ["0.0.0.0/0"]
  target_tags        = ["haproxy"]
}
