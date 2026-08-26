output "server_id" {
  description = "Numeric ID of the provisioned box."
  value       = hcloud_server.mail.id
}

output "ipv4_address" {
  description = "Public IPv4 of the box. Mail, git and Gemini resolve directly here by design."
  value       = hcloud_server.mail.ipv4_address
}

output "ipv6_address" {
  description = "Public IPv6 of the box."
  value       = hcloud_server.mail.ipv6_address
}
