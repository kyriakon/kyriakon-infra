# Snapshots have a description, not a name — select by label and always take
# the newest matching snapshot, so a re-snapshot after a patch cycle is picked
# up without editing this file.
data "hcloud_image" "openbsd" {
  with_selector     = var.snapshot_selector
  most_recent       = true
  with_architecture = "x86"
}

resource "hcloud_server" "mail" {
  name        = var.server_name
  server_type = var.server_type
  location    = var.location
  image       = data.hcloud_image.openbsd.id

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }
}
