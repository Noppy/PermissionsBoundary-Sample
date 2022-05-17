resource "aws_iam_policy" "high_authority_pb_policy" {
  name        = "PB-HighAuthority-Policy"
  path        = "/"
  description = "Permissions Boundary for Tenant's Hight Authority IAM Users/Roles"

  policy = templatefile(
    "iam_pb_high_authority_policy.tpl",
    {
      account_id = "${data.aws_caller_identity.current.account_id}"
    }
  )
}

resource "aws_iam_policy" "general_pb_policy" {
  name        = "PB-General-Policy"
  path        = "/"
  description = "Permissions Boundary for Tenant's General IAM Users/Roles"

  policy = templatefile(
    "iam_pb_general_policy.tpl",
    {
      account_id = "${data.aws_caller_identity.current.account_id}"
    }
  )
}