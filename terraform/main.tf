# Snapshots have a description, not a name - select by label and always take
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

  # The live box must never be rebuilt from whatever the selector currently
  # resolves to. `image` is ForceNew in the provider, so a change to the data
  # source is not an in-place update: it is destroy and recreate, and the server
  # it would destroy is the only copy of the mail. The selector moves on its own
  # as snapshots are taken and relabelled, and the existing server's image is a
  # historical fact about when it was built, not a setting to keep in sync.
  lifecycle {
    ignore_changes = [image]
  }

  # Both default to false in the provider. Declaring them is what stops a later
  # apply, which sees the defaults as the desired state, from quietly removing
  # protection from the only copy of the mail. Rebuild protection matters for the
  # same reason as delete: a rebuild replaces the root disk with an image.
  delete_protection  = true
  rebuild_protection = true

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }
}
