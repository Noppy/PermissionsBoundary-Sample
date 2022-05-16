#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  _do_FileCopy.py
#  ======
#  Copyright (C) 2022 n.fujita
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
from __future__ import print_function
from distutils.errors import CCompilerError
from http.client import FAILED_DEPENDENCY

import sys
import json
import time
import botocore
import boto3

Tenant_AdminRoleName       = 'Tenant-Admin-Role'
Tenant_AdminUserName       = 'Tenant-Admin-User'
Tenant_GeneralRoleName     = 'Tenant-General-Role'
Tenant_GeneralUserName     = 'Tenant-General-User'

CCoE_AdminRoleName         = 'CCoE-Admin-Role'
CCoE_AdminUserName         = 'CCoE-Admin-User' 

PB_HighAuthorityPolicyName = 'PB-HighAuthority-Policy'
PB_GeneralPolicyName       = 'PB-General-Policy'

#Return code
ret_failed = 'Failed'
ret_OK ='OK'
ret_NG = 'NG'

def dump_json( message ):
    json.dump(
        message,
        sys.stdout,
        ensure_ascii=False,
        indent=2,
        default=str
    )
    print ('\n')
#----------------------------------
# Delete Tenant Admin Role/User
#----------------------------------
def chek_deny_pb_High_authority_from_role(session, debug):
    try:
        Title  = 'No1.Verify that Delete High Authority PB Policy fails from the admin role.'
        result = ret_failed

        ret = None
        ret = session.client('iam').delete_role_permissions_boundary(
            RoleName = Tenant_AdminRoleName
        )
    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        #このテストはAccessDeniedにならないといけない
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

def chek_deny_pb_High_authority_from_user(session, debug):
    try:
        Title  = 'No1.Verify that Delete High Authority PB Policy fails from the admin user.'
        result = ret_failed
        ret = None
        ret = session.client('iam').delete_user_permissions_boundary(
            UserName = Tenant_AdminUserName
        )
    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        #このテストはAccessDeniedにならないといけない
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )



#----------------------------------
# Delete Tenant Geleral Role/User
#----------------------------------
def chek_deny_pb_general_from_role(session, debug):
    try:
        Title  = 'No1.Verify that Delete General PB Policy fails from the General role.'
        result = ret_failed
        ret = None
        ret = session.client('iam').delete_role_permissions_boundary(
            RoleName = Tenant_GeneralRoleName
        )
    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        #このテストはAccessDeniedにならないといけない
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

def chek_deny_pb_general_from_user(session, debug):
    try:
        Title  = 'No1.Verify that Delete General PB Policy fails from the General user.'
        result = ret_failed
        ret = None
        ret = session.client('iam').delete_user_permissions_boundary(
            UserName = Tenant_GeneralUserName
        )
    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        #このテストはAccessDeniedにならないといけない
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

#----------------------------------
# Delete PB
#----------------------------------
def chek_deny_delete_pb_high_authority_policy(session, debug):
    try:
        Title  = 'No2.Verify that Delete High Authority PB Policy fails.'
        result = ret_failed
        ret = None

        ident = session.client('sts').get_caller_identity()
        accountid = ident['Account']

        ret = session.client('iam').delete_policy(
            PolicyArn = 'arn:aws:iam::{}:policy/{}'.format( accountid,PB_HighAuthorityPolicyName )
        )
    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        #このテストはAccessDeniedにならないといけない
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

def chek_deny_delete_pb_general_policy(session, debug):
    try:
        Title  = 'No2.Verify that Delete General PB Policy fails.'
        result = ret_failed
        ret = None

        ident = session.client('sts').get_caller_identity()
        accountid = ident['Account']

        ret = session.client('iam').delete_policy(
            PolicyArn = 'arn:aws:iam::{}:policy/{}'.format( accountid,PB_GeneralPolicyName )
        )
    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        #このテストはAccessDeniedにならないといけない
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

#----------------------------------
# Create PB Policy version
#----------------------------------
def chek_deny_create_pb_high_authority_policy_version(session, debug):
    try:
        Title  = 'No2.Verify that Create High Authority PB Policy version fails.'
        result = ret_failed
        ret = None

        Policy = {
            "Version": "2012-10-17",
            "Statement": [
                {   
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }

        ident = session.client('sts').get_caller_identity()
        accountid = ident['Account']

        ret = session.client('iam').create_policy_version(
            PolicyArn = 'arn:aws:iam::{}:policy/{}'.format( accountid,PB_HighAuthorityPolicyName ),
            PolicyDocument = json.dumps(Policy)
        )
    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        #このテストはAccessDeniedにならないといけない
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

def chek_deny_create_pb_general_policy_version(session, debug):
    try:
        Title  = 'No2.Verify that Create General PB Policy version fails.'
        result = ret_failed
        ret = None

        Policy = {
            "Version": "2012-10-17",
            "Statement": [
                {   
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }

        ident = session.client('sts').get_caller_identity()
        accountid = ident['Account']

        ret = session.client('iam').create_policy_version(
            PolicyArn = 'arn:aws:iam::{}:policy/{}'.format( accountid,PB_GeneralPolicyName ),
            PolicyDocument = json.dumps(Policy)
        )
    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        #このテストはAccessDeniedにならないといけない
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

#----------------------------------
# Delete PB Policy version
#----------------------------------
def chek_deny_delete_pb_high_authority_policy_version(session, debug):
    try:
        Title  = 'No2.Verify that Delete High Authority PB Policy version fails.'
        result = ret_failed
        ret = None

        ident = session.client('sts').get_caller_identity()
        accountid = ident['Account']

        ret = session.client('iam').delete_policy_version(
            PolicyArn = 'arn:aws:iam::{}:policy/{}'.format( accountid,PB_HighAuthorityPolicyName ),
            VersionId = 'v1'
        )
    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        #このテストはAccessDeniedにならないといけない
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

def chek_deny_delete_pb_general_policy_version(session, debug):
    try:
        Title  = 'No2.Verify that Delete General PB Policy version fails.'
        result = ret_failed
        ret = None

        ident = session.client('sts').get_caller_identity()
        accountid = ident['Account']

        ret = session.client('iam').delete_policy_version(
            PolicyArn = 'arn:aws:iam::{}:policy/{}'.format( accountid,PB_GeneralPolicyName ),
            VersionId = 'v1'
        )
    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        #このテストはAccessDeniedにならないといけない
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )


#----------------------------------
# Update/Delete CCoE Role
#----------------------------------
# delete Role
def check_delete_ccoe_role(session, debug):
    try:
        Title  = 'No4.Verify that deleting CCoE-role fails.'
        result = ret_failed
        ret = None

        ret = session.client('iam').delete_role(
            RoleName = CCoE_AdminRoleName
        )

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        #このテストは失敗しないといけない
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

# update Role-1
def chek_update_ccoe_role(session, debug):
    try:
        Title  = 'No4.Verify that updating a ccoe role fails(update_role) fails.'
        result = ret_failed
        ret = None

        ident = session.client('sts').get_caller_identity()
        accountid = ident['Account']

        ret = session.client('iam').update_role(
            RoleName = CCoE_AdminRoleName,
            MaxSessionDuration = 18000 #5 hours
        )

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        #このテストはロールの作成が成功しないといけない
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )


# update Role-2
def chek_update_description_ccoe_role(session, debug):
    try:
        Title  = 'No4.Verify that updating ccoe role description fails.'
        result = ret_failed
        ret = None

        ident = session.client('sts').get_caller_identity()
        accountid = ident['Account']

        ret = session.client('iam').update_role_description(
            RoleName = CCoE_AdminRoleName,
            Description = 'Hoge Hoge Hoge Hoge'
        )

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

# update assumerole
def chek_update_assumerole_ccoe_role(session, debug):
    try:
        Title  = 'No4.Verify that updating assume role at ccoe role fails.'
        result = ret_failed
        ret = None

        ident = session.client('sts').get_caller_identity()
        accountid = ident['Account']

        assume = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [ "sts:AssumeRole" ],
                    "Principal": { "Service": [ "ec2.amazonaws.com"] }
                }
            ]
        }

        ret = session.client('iam').update_assume_role_policy(
            RoleName = CCoE_AdminRoleName,
            PolicyDocument = json.dumps(assume)
        )

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        #このテストはロールの作成が成功しないといけない
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

# add managed policy
def check_add_managed_policy_to_ccoe_role(session, debug):
    try:
        Title  = 'No4.Verify that adding a managed policy to ccoe role fails.'
        result = ret_failed
        ret = None

        ret = session.client('iam').attach_role_policy(
            RoleName  = CCoE_AdminRoleName,
            PolicyArn = 'arn:aws:iam::aws:policy/AdministratorAccess'
        )

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

# delete managed policy
def check_delete_managed_policy_to_ccoe_role(session, debug):
    try:
        Title  = 'No4.Verify that deleting a managed policy to ccoe role fails.'
        result = ret_failed
        ret = None

        ret = session.client('iam').detach_role_policy(
            RoleName  = CCoE_AdminRoleName,
            PolicyArn = 'arn:aws:iam::aws:policy/AdministratorAccess'
        )

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

# add inline policy
def check_add_inline_policy_to_ccoe_role(session, debug):
    try:
        Title  = 'No4.Verify that adding a inline policy to ccoe role fails.'
        result = ret_failed
        ret = None

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }

        ret = session.client('iam').put_role_policy(
            RoleName   = CCoE_AdminRoleName,
            PolicyName = 'HogeHoge-DenyAll-Policy' ,
            PolicyDocument = json.dumps(policy)
        )

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

# delete inline policy
def check_delete_inline_policy_to_ccoe_role(session, debug):
    try:
        Title  = 'No4.Verify that deleting a inline policy to ccoe role fails.'
        result = ret_failed
        ret = None

        ret = session.client('iam').delete_role_policy(
            RoleName   = CCoE_AdminRoleName,
            PolicyName = 'HogeHoge-DenyAll-Policy'
        )

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

def chek_change_pb_of_ccoe_role(session, debug):
    try:
        Title  = 'No4.Verify that attaching the general PB to ccoe role fails.'
        result = ret_failed
        ret = None

        ret = session.client('iam').put_role_permissions_boundary(
            RoleName = CCoE_AdminRoleName,
            PermissionsBoundary = 'arn:aws:iam::aws:policy/AdministratorAccess'
        )
    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )


#----------------------------------
# Update/Delete CCoE User
#----------------------------------
# delete ccoe user
def chek_delete_ccoe_user(session, debug):
    try:
        Title  = 'No4.Verify that deleting ccoe user.'
        result = ret_failed
        ret = None

        ret = session.client('iam').delete_user(
            UserName = CCoE_AdminUserName
        )

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

# attach pb to ccoe user
def chek_attach_pb_to_ccoe_user(session, debug):
    try:
        Title  = 'No4.Verify that adding  PB to ccoe user fails.'
        result = ret_failed
        ret = None

        ret = session.client('iam').put_user_permissions_boundary(
            UserName = CCoE_AdminUserName,
            PermissionsBoundary = 'arn:aws:iam::aws:policy/AdministratorAccess'
        )
    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

# add managed policy
def check_add_managed_policy_to_ccoe_user(session, debug):
    try:
        Title  = 'No4.Verify that adding a managed policy to ccoe user fails.'
        result = ret_failed
        ret = None

        ret = session.client('iam').attach_user_policy(
            UserName  = CCoE_AdminUserName,
            PolicyArn = 'arn:aws:iam::aws:policy/AdministratorAccess'
        )

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

# delete managed policy
def check_delete_managed_policy_to_ccoe_user(session, debug):
    try:
        Title  = 'No4.Verify that deleting a managed policy to ccoe role successes.'
        result = ret_failed
        ret = None

        ret = session.client('iam').detach_user_policy(
            UserName  = CCoE_AdminUserName,
            PolicyArn = 'arn:aws:iam::aws:policy/AdministratorAccess'
        )

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )


# add inline policy
def check_add_inline_policy_to_ccoe_user(session, debug):
    try:
        Title  = 'No4.Verify that adding a inline policy to ccoe user fails.'
        result = ret_failed
        ret = None

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }

        ret = session.client('iam').put_user_policy(
            UserName   = CCoE_AdminUserName,
            PolicyName = 'HogeHoge-DenyAll-Policy' ,
            PolicyDocument = json.dumps(policy)
        )

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

# delete inline policy
def check_delete_inline_policy_to_ccoe_user(session, debug):
    try:
        Title  = 'No4.Verify that deleting a inline policy to ccoe user fails.'
        result = ret_failed
        ret = None

        ret = session.client('iam').delete_user_policy(
            UserName   = CCoE_AdminUserName,
            PolicyName = 'HogeHoge-DenyAll-Policy'
        )

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )


# create login password
def check_create_login_passwd_to_ccoe_user(session, debug):
    try:
        Title  = 'No4.Verify that create login password to ccoe user fails.'
        result = ret_failed
        ret = None

        ret = session.client('iam').create_login_profile(
            UserName = CCoE_AdminUserName,
            Password ='Aiafbeua7523@'
        )
        time.sleep(60)

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

# update login password
def check_update_login_passwd_to_ccoe_user(session, debug):
    try:
        Title  = 'No4.Verify that update login password to ccoe user fails.'
        result = ret_failed
        ret = None

        ret = session.client('iam').update_login_profile(
            UserName = CCoE_AdminUserName,
            Password ='Kbadfbeia73nba@'
        )

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )



# delete login password
def check_delete_login_passwd_to_ccoe_user(session, debug):
    try:
        Title  = 'No4.Verify that delete login password to ccoe user fails.'
        result = ret_failed
        ret = None

        ret = session.client('iam').delete_login_profile(
            UserName = CCoE_AdminUserName
        )

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

# create access key
def check_create_access_key_to_ccoe_user(session, debug):
    try:
        Title  = 'No4.Verify that create a access key to ccoe user fails.'
        result = ret_failed
        ret = None

        ret = session.client('iam').create_access_key(
            UserName = CCoE_AdminUserName
        )

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

# update access key
def check_update_access_key_to_ccoe_user(session, debug):
    try:
        Title  = 'No4.Verify that update a access key to ccoe user fails.'
        result = ret_failed
        ret = None

        ret = session.client('iam').update_access_key(
            UserName    = CCoE_AdminUserName,
            AccessKeyId = 'AKIAZEGETO7AO4JJVCWQ',
            Status      = 'Inactive'
        )

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

# delete access key
def check_delete_access_key_to_ccoe_user(session, debug):
    try:
        Title  = 'No4.Verify that delete a access key to ccoe user fails.'
        result = ret_failed
        ret = None

        ret = session.client('iam').delete_access_key(
            UserName    = CCoE_AdminUserName,
            AccessKeyId = 'AKIAZEGETO7AO4JJVCWQ'
        )

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

# enable mfa device
def check_enable_mfa_device_to_ccoe_user(session, debug):
    try:
        Title  = 'No4.Verify that enable MFA device and associates it with ccoe user fails.'
        result = ret_failed
        ret = None

        ret = session.client('iam').enable_mfa_device(
            UserName     = CCoE_AdminUserName,
            SerialNumber = 'arn:aws:iam::627477542848:mfa/aahahaa',
            AuthenticationCode1  = '999999',
            AuthenticationCode2  = '000000'
        )

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )

# resync mfa device
def check_enable_mfa_device_to_ccoe_user(session, debug):
    try:
        Title  = 'No4.Verify that resync MFA device that is associated with ccoe user fails.'
        result = ret_failed
        ret = None

        ret = session.client('iam').resync_mfa_device(
            UserName     = CCoE_AdminUserName,
            SerialNumber = 'arn:aws:iam::627477542848:mfa/aahahaa',
            AuthenticationCode1  = '999999',
            AuthenticationCode2  = '000000'
        )

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )


# deactivate mfa device
def check_enable_mfa_device_to_ccoe_user(session, debug):
    try:
        Title  = 'No4.Verify that deactivate MFA device that is associated with ccoe user fails.'
        result = ret_failed
        ret = None

        ret = session.client('iam').deactivate_mfa_device(
            UserName     = CCoE_AdminUserName,
            SerialNumber = 'arn:aws:iam::627477542848:mfa/aahahaa'
        )

    except botocore.exceptions.ClientError as e:
        message = e.response
        if e.response['Error']['Code'] == 'AccessDenied':
            result = ret_OK
        else:
            result = ret_failed
    else:
        message = ret
        result = ret_NG
    finally:
        if debug:
            dump_json( message = message )
        return( { 'Title':  Title, 'Result': result } )