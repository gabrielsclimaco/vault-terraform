output "pem" {
  value       = tls_private_key.vault.private_key_pem
  sensitive   = true
  description = "Key pair private key pem for Vault's server"
}
