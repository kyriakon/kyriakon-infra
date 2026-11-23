# The provisioning image is pinned by numeric ID, never by a label selector: a
# label is mutable, so anyone holding HCLOUD_TOKEN could give a snapshot of the
# live box the provisioning label and have the next create boot it, disk and
# all. The ID and its description are recorded in the pinned-image table in
# docs/runbook.md, which is the review surface, and the preconditions on the
# server below refuse a plan whose pair disagrees.
data "hcloud_image" "openbsd" {
  id = var.image_id
}

resource "hcloud_server" "mail" {
  name        = var.server_name
  server_type = var.server_type
  location    = var.location
  image       = data.hcloud_image.openbsd.id

  lifecycle {
    # `image` is ForceNew in the provider, so a change to the variable is not an
    # in-place update: it is destroy and recreate, and the server it would
    # destroy is the only copy of the mail. The live box must never be rebuilt
    # by an apply. The existing server's image is a historical fact about when
    # it was built, not a setting to keep in sync, so a newer reviewed image is
    # picked up by a deliberate rebuild, not by a variable edit here.
    #
    # `server_type` is ignored for the same console reason as `public_net`
    # below: the provider's update path for a type change powers the server
    # off, changes the type, and does not power it back on, so an apply leaves
    # the box off at the softraid passphrase prompt. A resize is a hand step in
    # the Hetzner console (docs/runbook.md, "How much the box carries"), and
    # `terraform plan` should show no diff after one.
    #
    # Preconditions, not a `check` block: a check assertion only warns and the
    # plan still exits 0, while these fail it. They are evaluated on every plan
    # that includes this resource, not only when it is being replaced, because
    # they defend the image a state-loss rebuild would boot more than they
    # defend a diff. The second guards an ID that resolves somewhere
    # unintended, retyped, reused, or a live-box snapshot.
    precondition {
      condition     = data.hcloud_image.openbsd.description == var.image_description
      error_message = "Image ${var.image_id} is described \"${data.hcloud_image.openbsd.description}\", not \"${var.image_description}\". Set both variables from `hcloud image list` and record them together in docs/runbook.md."
    }

    precondition {
      condition     = data.hcloud_image.openbsd.architecture == "x86"
      error_message = "Image ${var.image_id} is ${data.hcloud_image.openbsd.architecture}, not x86; the server types this stack uses are x86."
    }

    ignore_changes = [image, server_type]

    # Terraform is refused the chance to plan this server's removal at all, replacement
    # included, since any ForceNew change plans as a destroy. delete_protection below is
    # the provider's refusal, which only helps if the request gets that far; this is the
    # plan-time one. Together with the live root's state never appearing in
    # terraform/throwaway, a mistaken destroy meets three independent refusals. Removing
    # this line is the deliberate ceremony for a rebuild.
    prevent_destroy = true
  }

  # Both default to false in the provider. Declaring them is what stops a later
  # apply, which sees the defaults as the desired state, from quietly removing
  # protection from the only copy of the mail. Rebuild protection matters for the
  # same reason as delete: a rebuild replaces the root disk with an image.
  delete_protection  = true
  rebuild_protection = true

  # Off, and declared so on purpose: restic on the storage box is the copy
  # (scripts/backup.sh, proven by the weekly restore test), not Hetzner's own
  # backups. Leaving this undeclared means a console enable is planned back off
  # without a line in this file to explain it; declared, the correction is still
  # applied, but the intent is visible to a reviewer.
  backups = false

  # public_net is deliberately not declared. The provider's update path for it
  # powers the server off, does its work, and powers it back on, and this box
  # needs its softraid passphrase typed at the console on every boot, so any
  # public_net diff that reaches apply costs an outage until someone is at a
  # keyboard. The block only matters at creation, and omitting it still gets both
  # primary IPs generated, which is all it was asking for. The provider also
  # suppresses the diff when the block is absent, so state and config agree
  # without it.
}
