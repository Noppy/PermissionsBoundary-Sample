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
            "Sid": "No1DenyHighAuthorityActionsIAMWriteWithoutCreateDelete",
            "Effect": "Deny",
            "Action": [
                "iam:Add*",
                "iam:Attach*",
                "iam:Detach*",
                "iam:Put*",
                "iam:Remove*",
                "iam:Reset*",
                "iam:Set*",
                "iam:Tag*",
                "iam:Untag*",
                "iam:Upload*"
            ],
            "Resource": "*"
        },
        {
            "Sid": "DenyHighAuthorityActionsIAMWriteCreateDelete",
            "Effect": "Deny",
            "Action": [
                "iam:CreateGroup",
                "iam:CreateUser",
                "iam:CreateRole",
                "iam:CreatePolicy",
                "iam:CreatePolicyVersion",
                "iam:CreateInstanceProfile",
                "iam:CreateServiceSpecificCredential",
                "iam:CreateOpenIDConnectProvider",
                "iam:CreateSAMLProvider",
                "iam:CreateAccountAlias",
                "iam:DeleteGroup",
                "iam:DeleteUser",
                "iam:DeleteRole",
                "iam:DeletePolicy",
                "iam:DeletePolicyVersion",
                "iam:DeleteUserPolicy",
                "iam:DeleteGroupPolicy",
                "iam:DeleteRolePolicy",
                "iam:DeleteInstanceProfile",
                "iam:DeleteRolePermissionsBoundary",
                "iam:DeleteUserPermissionsBoundary",
                "iam:DeleteServiceLinkedRole",
                "iam:DeleteAccountPasswordPolicy",
                "iam:DeleteServiceSpecificCredential",
                "iam:DeleteOpenIDConnectProvider",
                "iam:DeleteSAMLProvider",
                "iam:DeleteAccountAlias",
                "iam:DeleteServerCertificate",
                "iam:DeleteSigningCertificate",
                "iam:UpdateGroup",
                "iam:UpdateUser",
                "iam:UpdateRole",
                "iam:UpdateRoleDescription",
                "iam:UpdateAssumeRolePolicy",
                "iam:UpdateAccountPasswordPolicy",
                "iam:UpdateServiceSpecificCredential",
                "iam:UpdateOpenIDConnectProviderThumbprint",
                "iam:UpdateSAMLProvider",
                "iam:UpdateServerCertificate",
                "iam:UpdateSigningCertificate"
            ],
            "Resource": "*"
        },
        {
            "Sid": "No4bDenyPolicyUpdatesForExistingUsers",
            "Effect": "Deny",
            "Action": [
                "iam:UpdateLoginProfile",
                "iam:CreateLoginProfile",
                "iam:DeleteLoginProfile",                
                "iam:DeleteAccessKey",
                "iam:UpdateAccessKey",
                "iam:CreateAccessKey",
                "iam:DeactivateMFADevice",
                "iam:EnableMFADevice",
                "iam:ResyncMFADevice"
            ],
            "Resource": [
                "arn:aws:iam::${account_id}:user/CCoE-Admin-User"
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