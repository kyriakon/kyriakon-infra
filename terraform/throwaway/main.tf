# The restore test's box. It exists for the minutes the test takes, once a week, and is
# destroyed afterwards, so everything here is written to be disposable.
#
# scripts/restore-standup.sh drives it: apply, read the address, run the test over ssh,
# destroy. The destroy sits in that script's EXIT trap, which is why the state file is
# load-bearing and why this root must never grow a reference to the mail box.
data "hcloud_image" "restore" {
  with_selector     = var.snapshot_selector
  most_recent       = true
  with_architecture = "x86"
}

resource "hcloud_server" "restore" {
  name        = var.server_name
  server_type = var.server_type
  location    = var.location
  image       = data.hcloud_image.restore.id

  # Matches the label the old standing box carried, so anything in the console that is
  # left over from a killed run is recognisable as this and nothing else.
  labels = {
    role = "restore-test"
  }

  # No ssh_keys block. The key that gets in is already in the template snapshot's
  # /root/.ssh/authorized_keys, which is what keeps the template self-contained and
  # keeps the private half off the box being created.

  # No delete_protection and no rebuild_protection, unlike the live root. A box that
  # refuses to die is the failure this root exists to avoid, and the cost of losing
  # this one is a single skipped test.

  # Deliberately no lifecycle ignore_changes on image, again the opposite of the live
  # root: a new template snapshot should be picked up by the next run, which is how a
  # patched template reaches the test without anyone remembering an image id.
}
