{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowAllActions",
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        },
        {
            
            "Sid": "No1DenyPBControl",
            "Effect": "Deny",
            "Action": [
                "iam:DeleteRolePermissionsBoundary",
                "iam:DeleteUserPermissionsBoundary"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "iam:PermissionsBoundary": [
                        "arn:aws:iam::${account_id}:policy/PB-HighAuthority-Policy",
                        "arn:aws:iam::${account_id}:policy/PB-General-Policy"
                    ]
                }
            }
        },
        {
            "Sid": "No2DenyPBPolicyControl",
            "Effect": "Deny",
            "Action": [
                "iam:CreatePolicyVersion",
                "iam:DeletePolicy",
                "iam:DeletePolicyVersion",
                "iam:SetDefaultPolicyVersion"
            ],
            "Resource": [
                "arn:aws:iam::${account_id}:policy/PB-HighAuthority-Policy",
                "arn:aws:iam::${account_id}:policy/PB-General-Policy"
            ]
        },
        {
            "Sid": "No3AllowIAMActionConditionalPermissions",
            "Effect": "Deny",
            "Action": [
                "iam:CreateRole",
                "iam:PutRolePermissionsBoundary",
                "iam:CreateUser",
                "iam:PutUserPermissionsBoundary"
            ],
            "Resource": "*",
            "Condition": {
                "StringNotEquals": {
                    "iam:PermissionsBoundary": [
                        "arn:aws:iam::${account_id}:policy/PB-General-Policy"
                    ]
                }
            }
        },
        {
            "Sid": "No4aDenyPolicyUpdatesForExistingRoles",
            "Effect": "Deny",
            "Action": [
                "iam:DeleteRole",
                "iam:UpdateRole",
                "iam:UpdateRoleDescription",
                "iam:AttachRolePolicy",
                "iam:DeleteRolePolicy",
                "iam:DetachRolePolicy",
                "iam:PutRolePolicy",
                "iam:UpdateAssumeRolePolicy"
            ],
            "Resource":[
                "arn:aws:iam::${account_id}:role/CCoE-Admin-Role"
            ]
        },
        {
            "Sid": "No4bDenyPolicyUpdatesForExistingUsers",
            "Effect": "Deny",
            "Action": [
                "iam:UpdateUser",
                "iam:DeleteUser",
                "iam:AttachUserPolicy",
                "iam:DeleteUserPolicy",
                "iam:DetachUserPolicy",
                "iam:PutUserPolicy",
                "iam:UpdateAssumeRolePolicy"
            ],
            "Resource": [
                "arn:aws:iam::${account_id}:user/CCoE-Admin-User"
            ]
        },
        {
            "Sid": "No4cDenyPolicyUpdatesForExistingGroups",
            "Effect": "Deny",
            "Action": [
                "iam:AddUserToGroup",
                "iam:UpdateGroup",
                "iam:DeleteGroup",
                "iam:RemoveUserFromGroup",
                "iam:RemoveUserFromGroup",
                "iam:DeleteGroup",
                "iam:AttachGroupPolicy",
                "iam:UpdateGroup",
                "iam:DetachGroupPolicy",
                "iam:DeleteGroupPolicy",
                "iam:PutGroupPolicy"
            ],
            "Resource": [
                "arn:aws:iam::${account_id}:group/CCoE-Admin-Group"
            ]
        },
        {
            "Sid": "DenyHighAuthorityActions",
            "Effect": "Deny",
            "Action": [
                "iam:CreateOpenIDConnectProvider",
                "iam:DeleteOpenIDConnectProvider",
                "iam:UpdateOpenIDConnectProviderThumbprint",
                "iam:AddClientIDToOpenIDConnectProvider",
                "iam:RemoveClientIDFromOpenIDConnectProvider",
                "iam:CreateSAMLProvider",
                "iam:DeleteSAMLProvider",
                "iam:UpdateSAMLProvider",
                "iam:CreateAccountAlias",
                "iam:DeleteAccountAlias",
                "ec2:AttachInternetGateway",
                "ec2:Accept*",
                "ec2:CreateEgressOnlyInternetGateway",
                "ec2:AttachVpnGateway",
                "ec2:CreateClientVpnEndpoint",
                "ec2:ModifyClientVpnEndpoint",
                "ec2:CreateVpcEndpoint",
                "ec2:CreateVpcEndpointServiceConfiguration",
                "ec2:ModifyVpcEndpointServiceConfiguration",
                "ec2:ModifyVpcEndpointServicePermissions",
                "ec2:CreateVpcPeeringConnection",
                "ec2:CreateTransitGatewayPeeringAttachment",
                "ec2:CreateTransitGatewayVpcAttachment",
                "ec2:ModifyTransitGatewayVpcAttachment",
                "ec2:ModifyImageAttribute",
                "ec2:ModifySnapshotAttribute"
            ],
            "Resource": "*"
        }
    ]
}