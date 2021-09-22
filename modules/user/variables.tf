variable "username" {
  type        = string
  description = "The username for the user. Accepted characters: alphanumeric plus '_', '-', '.' (underscore, hyphen and period); username cannot begin with hyphen or period."
}

variable "password" {
  type        = string
  description = "Password used only for creation. Advise users to change this on first access."
  default     = "mudar123"
}

variable "accessor" {
  type        = string
  description = "Accessor of the mount (from auth method) to which the alias should belong to."
}

variable "policies" {
  type        = list(string)
  description = "List of policies names to attach to user"
  default     = []
}
