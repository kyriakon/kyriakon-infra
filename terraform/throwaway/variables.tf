variable "server_name" {
  description = "Name for the throwaway box. Static rather than dated on purpose: a run killed before its destroy leaves the box in state, and the next apply then adopts it instead of colliding on the name."
  type        = string
  default     = "kyriakon-restore-test"
}

variable "server_type" {
  description = "Hetzner Cloud server type. Its disk must be at least the template snapshot's source disk, and the box only has to hold the restored tree for the length of one test."
  type        = string
  default     = "cx23"
}

variable "location" {
  description = "Hetzner Cloud location. fsn1 rather than the live box's region on purpose: the storage box is in fsn1 and is what this box restores from, so the test runs over the path it will actually use. The live root's rule about staying out of the storage box's region is about one outage taking both copies of the mail, which a box that exists for five minutes cannot affect."
  type        = string
  default     = "fsn1"
}

variable "snapshot_selector" {
  description = "Label selector for the restore-test template snapshot, the one carrying the test scripts, the repository password and the read-only storage sub-account key. Point-in-time copies of the live box are labelled `kind=dr` and provisioning images `kind=gold`, so neither can be picked up here by accident."
  type        = string
  default     = "kind=restore"
}
