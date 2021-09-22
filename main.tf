terraform {
  backend "s3" {
    bucket = "coffee-terraform-states"
    key    = "vault/terraform.tfstate"
    region = "us-east-1"
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.27"
    }
  }
}

# AWS

provider "aws" {
  region = "us-east-1"
}

module "server" {
  source = "./modules/server"

  vault_bucket_name = "coffee-article-vault"
}

data "aws_instance" "server" {
  instance_tags = {
    Name = "Vault"
  }
}

# Vault

provider "vault" {
  address = "http://${data.aws_instance.server.public_ip}"
  token   = var.vault_token
}

# Locals

locals {
  projects = toset([
    "project-x",
    "project-y",
    "project-z",
  ])
  policies = {
    for project in local.projects : project => {
      maintainer = "${project}_maintainer"
      member     = "${project}_member"
      visitor    = "${project}_visitor"
    }
  }
  admins = toset(["pessoa.a"])
  users = {
    "pessoa.b" = [
      local.policies["project-x"]["maintainer"],
      local.policies["project-y"]["maintainer"],
    ]
    "pessoa.c" = [
      local.policies["project-y"]["member"],
      local.policies["project-z"]["member"],
    ]
    "pessoa.d" = [
      local.policies["project-z"]["visitor"],
    ]
  }
}

# Projects

module "projects" {
  for_each = local.projects
  source   = "./modules/project"

  name = each.key
}

# Auth backend

resource "vault_auth_backend" "userpass" {
  type = "userpass"
}

# Admin

data "vault_policy_document" "admin" {
  rule {
    path         = "*"
    description  = "Allow all on everything"
    capabilities = ["create", "read", "update", "delete", "list", "sudo"]
  }
}

resource "vault_policy" "admin" {
  name   = "admin"
  policy = data.vault_policy_document.admin.hcl
}

module "admins" {
  for_each = local.admins
  source   = "./modules/user"

  username = each.key
  accessor = vault_auth_backend.userpass.accessor
  policies = ["admin"]
}

# Users

module "users" {
  for_each = local.users
  source   = "./modules/user"

  username = each.key
  accessor = vault_auth_backend.userpass.accessor
  policies = each.value
}

# Secrets

resource "vault_generic_secret" "infraestructure_secrets" {
  for_each = local.projects

  path = "${each.key}/infraestrutcture/foo"

  data_json = jsonencode({
    "bar" = "baz"
  })
}

resource "vault_generic_secret" "service_secrets" {
  for_each = local.projects

  path = "${each.key}/service/foo"

  data_json = jsonencode({
    "bar" = "baz"
  })
}
