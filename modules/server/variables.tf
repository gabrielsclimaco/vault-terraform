variable "vault_bucket_name" {
  type        = string
  description = "The name of the bucket that will be used as backend for Vault"
}

variable "instance_types" {
  type        = list(string)
  description = "Instance type for server's EC2 instance"
  default     = ["t3.micro", "t3a.micro", "t2.micro"]
}
