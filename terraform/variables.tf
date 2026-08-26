variable "server_name" {
  description = "Hostname of the mail box. Host-identifying — set it in terraform.tfvars (gitignored), never hardcode it here."
  type        = string
}

variable "server_type" {
  description = "Hetzner Cloud server type. Its disk must be >= the snapshot's source disk (see the snapshot procedure)."
  type        = string
  default     = "cx23"
}

variable "location" {
  description = "Hetzner datacenter. Keep it in the region the backup storage box is NOT in."
  type        = string
  default     = "hel1"
}

variable "snapshot_selector" {
  description = "Label selector matching the OpenBSD snapshot, set at `hcloud server create-image --label ...` time. Snapshots have no name; the selector is the stable handle across re-snapshots."
  type        = string
  default     = "os=openbsd"
}
