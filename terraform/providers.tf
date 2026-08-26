terraform {
  required_version = ">= 1.5"

  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.68"
    }
  }
}

# The Hetzner Cloud API token comes from the HCLOUD_TOKEN environment
# variable, never from a committed file or a variable written to state.
provider "hcloud" {}
