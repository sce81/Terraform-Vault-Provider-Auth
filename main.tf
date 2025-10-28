resource "vault_jwt_auth_backend_role" "tfc_role" {
  backend        = var.jwt_backend_path
  role_name      = var.role_name
  token_policies = [vault_policy.tfc_policy.name]

  bound_audiences   = [var.tfc_vault_audience]
  bound_claims_type = "glob"
  bound_claims = {
    sub = "organization:${var.tfc_organization_name}:project:${var.target_tfc_project}:workspace:*:run_phase:*"
  }
  user_claim = "terraform_full_workspace"
  role_type  = "jwt"
  token_ttl  = 1200
}

resource "vault_policy" "tfc_policy" {
  name = var.role_name

  policy = var.vault_policy
}

