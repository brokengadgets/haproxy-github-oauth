# e2-micro in us-central1 qualifies for GCP's always-free tier (1 VM/month).

resource "google_compute_address" "haproxy" {
  name   = "haproxy-ip"
  region = var.region
}

resource "google_compute_instance" "haproxy" {
  name         = "haproxy"
  machine_type = var.haproxy_machine_type
  zone         = var.zone
  tags         = ["haproxy"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 10
      type  = "pd-standard"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.main.id
    access_config {
      nat_ip = google_compute_address.haproxy.address
    }
  }

  # Only non-secret config goes into the startup script / instance metadata.
  # Secrets are fetched at runtime from Secret Manager using the VM's SA.
  metadata = {
    startup-script = templatefile("${path.module}/templates/haproxy-init.sh.tftpl", {
      project_id  = var.project_id
      domain      = var.domain
      docker_ip   = var.docker_host_ip
      github_org  = var.github_org
    })
  }

  service_account {
    email  = google_service_account.haproxy.email
    scopes = ["cloud-platform"]
  }

  depends_on = [data.google_secret_manager_secret_version.check]
}
