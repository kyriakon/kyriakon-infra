output "ipv4_address" {
  description = "The throwaway box's IPv4 address, which scripts/restore-standup.sh reads to ssh in."
  value       = hcloud_server.restore.ipv4_address
}

output "server_id" {
  description = "The throwaway box's id, for finding it in the console if a run dies leaving it behind."
  value       = hcloud_server.restore.id
}
