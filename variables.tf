variable "role_name" {
  type = string
  default     = "terraform-role"
  description = "Name of jwt auth backend role"
}
variable "tfc_vault_audience" {
  type        = string
  default     = "vault.workload.identity"
  description = "The audience value to use in run identity tokens"
}
variable "tfc_organization_name" {
  type        = string
  description = "The name of your Terraform Cloud organization"
}
variable "target_tfc_project" {
  type        = string
  default     = "vault-configuration"
  description = "The project under which the vault authentication will be valid"
}
variable "tfc_project_name" {
  type        = string
  default     = "Default Project"
  description = "The project under which a workspace will be created"
}
variable "vault_policy" {
  type        = string
  default     = null
  description = "Vault Policy to assiciate with Terraform Platform"
}

variable "jwt_backend_path" {
  type        = string
  default     = "jwt"
  description = "Vault auth backend to associate role with"
}