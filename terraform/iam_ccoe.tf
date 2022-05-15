#-----------------
# CCoE-Admin Role
#-----------------
resource "aws_iam_role" "ccoe-admin-role" {
  name = "CCoE-Admin-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.trusted_role_name}"
        }
      }
    ]
  })

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AdministratorAccess"
  ]
}

#-----------------
# CCoE-Admin User and Group
#-----------------
# IAM Group
resource "aws_iam_group" "ccoe-admin-group" {
  name = "CCoE-Admin-Group"
  path = "/"
}

resource "aws_iam_group_policy_attachment" "attach-policy-to-ccoe-admin-group" {
  group      = aws_iam_group.ccoe-admin-group.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# IAM User
resource "aws_iam_user" "ccoe-admin-user" {
  name = "CCoE-Admin-User"

  path          = "/"
  force_destroy = true
}

resource "aws_iam_group_membership" "add-ccoe-admin-user-to-ccoe-admin-group" {
  name = "ccoe-admin-user-membership"

  users = [
    aws_iam_user.ccoe-admin-user.name
  ]

  group = aws_iam_group.ccoe-admin-group.name
}