terraform {
  required_version = ">= 1.5"

  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.68"
    }
  }
}

# The token comes from HCLOUD_TOKEN in the environment, as in the root above, so it is
# never in a committed file and never written to state.
provider "hcloud" {}

# This root exists to create one box a week and destroy it again, and its state file is
# the only thing that can reach that box. That separation is the safety property rather
# than tidiness: `terraform destroy` can only remove what is in the state it is run
# against, and the mail box lives in the state one directory up, which is applied by
# hand and never from cron.
#
# The rule that follows from it: nothing here may declare, reference or import anything
# from the live root. If a resource belonging to the mail box ever appears in this
# state, this root has become dangerous, and the answer is to stop using it rather than
# to add protection flags and hope.
