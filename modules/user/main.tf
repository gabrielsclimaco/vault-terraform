resource "vault_identity_entity" "user" {
  name     = var.username
  policies = var.policies
}

resource "vault_identity_entity_alias" "user" {
  name           = var.username
  mount_accessor = var.accessor
  canonical_id   = vault_identity_entity.user.id
}

resource "vault_generic_endpoint" "user" {
  depends_on           = [vault_identity_entity_alias.user]
  path                 = "auth/userpass/users/${var.username}"
  ignore_absent_fields = true

  data_json = jsonencode({
    "password" = var.password
  })

  lifecycle {
    ignore_changes = [data_json]
  }
}
