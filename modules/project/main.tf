# Policy documents

data "vault_policy_document" "maintainer" {
  rule {
    path         = "sys/mount"
    capabilities = ["read"]
    description  = "Allow read secrets engine"
  }

  rule {
    path         = "${var.name}/data/*"
    capabilities = ["create", "read", "update", "delete", "list", "sudo"]
    description  = "Manage ${var.name} secrets"
  }

  rule {
    path         = "${var.name}/metadata/*"
    capabilities = ["list", "read", "delete"]
    description  = "List ${var.name} secret keys and manage keys metadata"
  }

  rule {
    path         = "${var.name}/delete/*"
    capabilities = ["update"]
    description  = "Allow deleting any key version on ${var.name} secret engine"
  }

  rule {
    path         = "${var.name}/undelete/*"
    capabilities = ["update"]
    description  = "Allow deleting any key version on ${var.name} secret engine"
  }

  rule {
    path         = "${var.name}/destroy/*"
    capabilities = ["update"]
    description  = "Allow destroying key versions on ${var.name} secret engine"
  }
}

data "vault_policy_document" "member" {
  rule {
    path         = "sys/mount"
    capabilities = ["read"]
    description  = "Allow read secrets engine"
  }

  rule {
    path         = "${var.name}/data/*"
    capabilities = ["create", "read", "list"]
    description  = "View and create ${var.name} secrets"
  }

  rule {
    path         = "${var.name}/metadata/*"
    capabilities = ["list"]
    description  = "List ${var.name} secret keys"
  }
}

data "vault_policy_document" "visitor" {
  rule {
    path         = "sys/mount"
    capabilities = ["read"]
    description  = "Allow read secrets engine"
  }

  rule {
    path         = "${var.name}/data/*"
    capabilities = ["read", "list"]
    description  = "View ${var.name} secrets"
  }

  rule {
    path         = "${var.name}/metadata/*"
    capabilities = ["list"]
    description  = "List ${var.name} secret keys"
  }
}

# Policies

resource "vault_policy" "maintainer" {
  name   = "${var.name}_maintainer"
  policy = data.vault_policy_document.maintainer.hcl
}

resource "vault_policy" "member" {
  name   = "${var.name}_member"
  policy = data.vault_policy_document.member.hcl
}

resource "vault_policy" "visitor" {
  name   = "${var.name}_visitor"
  policy = data.vault_policy_document.visitor.hcl
}

# Secret engine

resource "vault_mount" "project" {
  path        = var.name
  type        = "kv-v2"
  description = "This is ${var.name} KV Version 2 secret engine mount"
}
