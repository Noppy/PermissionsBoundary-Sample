data "aws_caller_identity" "current" {}

variable "trusted_role_name" {
  default = "OrganizationAccountAccessRole"
}