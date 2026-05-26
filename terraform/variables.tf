variable "project_id" {
  description = "GCP project ID"
  type        = string
}

# Must be us-central1, us-east1, or us-west1 for the free-tier e2-micro.
variable "region" {
  type    = string
  default = "us-central1"
}

variable "zone" {
  type    = string
  default = "us-central1-a"
}

variable "domain" {
  type    = string
  default = "brokengadgets.io"
}

variable "github_org" {
  type    = string
  default = "brokengadgets"
}

variable "haproxy_machine_type" {
  description = "e2-micro is the free-tier eligible type"
  type        = string
  default     = "e2-micro"
}

variable "admin_source_ranges" {
  description = "CIDRs allowed to SSH. Lock this down to your IP(s)."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "docker_host_ip" {
  description = "VPN IP of the existing Docker host"
  type        = string
  default     = "10.99.0.2"
}

variable "openvpn_server_ip" {
  description = "Public IP of the OpenVPN server — used to scope the VPC firewall rules"
  type        = string
}

variable "openvpn_port" {
  description = "UDP port the OpenVPN server listens on"
  type        = number
  default     = 1194
}

# ── MIAB — only needed for DNS record management at apply time ────────────────
# These DO go into tfstate (inside null_resource triggers).
# They are not highly privileged — they only control DNS records, not mail data.
# If you want zero secrets in state, provision DNS records manually using
# the MIAB admin panel instead and set var.manage_miab_dns = false.

variable "miab_host" {
  description = "MIAB hostname for DNS record management"
  type        = string
}

variable "miab_user" {
  type      = string
  sensitive = true
}

variable "miab_password" {
  type      = string
  sensitive = true
}

variable "manage_miab_dns" {
  description = "Set to false to skip MIAB DNS record management (manage records manually instead)"
  type        = bool
  default     = true
}
