output "server_pem" {
  value       = module.server.pem
  sensitive   = true
  description = "Key pair private key pem for Vault's server"
}

output "server_ip" {
  value       = data.aws_instance.server.public_ip
  description = "Public IP of the EC2 instance acting as ECS custer"
}

// output "user_ids" {
//   value = {
//     pessoa_a = module.pessoa_a.id,
//     pessoa_b = module.pessoa_b.id,
//     pessoa_c = module.pessoa_c.id,
//     pessoa_d = module.pessoa_d.id,
//   }
// }
