# Terraform Vault Provider Auth
### All code is provided for reference purposes only and is used entirely at own risk. Code is for use in development environments only. Not intended for Production use. 

Configures Vault to trust Terraform to manage Vault at a specified location


##### Usage

    module "vault-auth" {
      source               = "git@github.com:sce81/Terraform-Vault-Provider-Auth.git"

        vault_url             = var.vault_url
        jwt_backend_path      = var.jwt_backend_path
        tfc_vault_audience    = var.tfc_vault_audience
        tfc_organization_name = var.tfc_organization_name
        tfc_project_name      = var.tfc_project_name
        tfc_workspace_name    = var.tfc_workspace_name
        vault_policy          = local.vault_policy
        vault_namespace       = var.vault_namespace
    }

#### Info


- HCP/Enterprise Terraform will configure Vault to trust workloads based on the identity of the Terraform instance executing the Terraform code.
- NB: Not compatible with Terraform Community Edition.
- The module should be called via a parent module detailing the configuration you require. Example located here: https://github.com/sce81/Terraform-Vault-Provider-Auth-Root-Module 
- The module will create a Vault JWT Auth backend called ${var.jwt_backend_path} .
- The module will create a Variable Set valid for Terraform Workspaces located with the target Project ${var.tfc_project_name}.
