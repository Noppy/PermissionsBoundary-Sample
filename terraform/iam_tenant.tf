
#-----------------
# Tenant-Admin Role
#-----------------
resource "aws_iam_role" "tenant-admin-role" {
  name = "Tenant-Admin-Role"

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
# tenant-Admin User and Group
#-----------------
# IAM Group
resource "aws_iam_group" "tenant-admin-group" {
  name = "Tenant-Admin-Group"
  path = "/"
}

resource "aws_iam_group_policy_attachment" "attach-policy-to-tenant-admin-group" {
  group      = aws_iam_group.tenant-admin-group.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# IAM User
resource "aws_iam_user" "tenant-admin-user" {
  name = "Tenant-Admin-User"

  path          = "/"
  force_destroy = true
}

resource "aws_iam_group_membership" "add-tenant-admin-user-to-tenant-admin-group" {
  name = "tenant-admin-user-membership"

  users = [
    aws_iam_user.tenant-admin-user.name
  ]

  group = aws_iam_group.tenant-admin-group.name
}

#-----------------
# Tenant-General Role
#-----------------
resource "aws_iam_role" "tenant-general-role" {
  name = "Tenant-General-Role"

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
# tenant-General User and Group
#-----------------
# IAM Group
resource "aws_iam_group" "tenant-general-group" {
  name = "Tenant-General-Group"
  path = "/"
}

resource "aws_iam_group_policy_attachment" "attach-policy-to-tenant-general-group" {
  group      = aws_iam_group.tenant-general-group.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# IAM User
resource "aws_iam_user" "tenant-general-user" {
  name = "Tenant-General-User"

  path          = "/"
  force_destroy = true
}

resource "aws_iam_group_membership" "add-tenant-general-user-to-tenant-general-group" {
  name = "tenant-general-user-membership"

  users = [
    aws_iam_user.tenant-general-user.name
  ]

  group = aws_iam_group.tenant-general-group.name
}