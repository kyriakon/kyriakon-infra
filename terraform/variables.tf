variable "server_name" {
  description = "Hostname of the mail box. Host-identifying - set it in terraform.tfvars (gitignored), never hardcode it here."
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

variable "image_id" {
  description = "Numeric ID of the reviewed OpenBSD provisioning snapshot. Pin the ID: a label selector is mutable, so anyone holding HCLOUD_TOKEN could point it at a snapshot of the live box. Change it only after building the image on a throwaway box (terraform/README.md section 1) and recording it in docs/runbook.md."
  type        = number
}

variable "image_description" {
  description = "Description of the image named by image_id, as set at `create-image` time. The plan check in main.tf compares it with the description the ID resolves to, so a mistyped or stale ID shows up during plan rather than at first boot."
  type        = string
}
