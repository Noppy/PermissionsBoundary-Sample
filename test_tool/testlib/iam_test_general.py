#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
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
from http.client import FAILED_DEPENDENCY

import sys
import json
import botocore
import boto3

Tenant_AdminRoleName       = 'Tenant-Admin-Role'
Tenant_AdminUserName       = 'Tenant-Admin-User'
Tenant_GeneralRoleName     = 'Tenant-General-Role'
Tenant_GeneralUserName     = 'Tenant-General-User'


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
# Create Role/User without PB
#----------------------------------
def chek_deny_create_role_without_pb(session, debug):
    try:
        Title  = 'No3.Verify that Create role fails.'
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
                    "Principal": { "Service": [ "lambda.amazonaws.com"] }
                }
            ]
        }
        ret = session.client('iam').create_role(
            RoleName = 'Tenant-Dummy-Role',
            AssumeRolePolicyDocument = json.dumps(assume)
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

def chek_deny_create_user_without_pb(session, debug):
    try:
        Title  = 'No3.Verify that Create user fails.'
        result = ret_failed
        ret = None

        ret = session.client('iam').create_user(
            UserName = 'Tenant-Dummy-User'
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
# change the PB applied to a Role/User
#----------------------------------
def chek_deny_change_pb_of_general_role(session, debug):
    try:
        Title  = 'No3.Verify that changing the general PB of the General Role to another policy fails.'
        result = ret_failed
        ret = None

        ret = session.client('iam').put_role_permissions_boundary(
            RoleName = Tenant_GeneralRoleName,
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

def chek_deny_change_pb_of_general_user(session, debug):
    try:
        Title  = 'No3.Verify that changing the general PB of the General user to another policy fails.'
        result = ret_failed
        ret = None

        ret = session.client('iam').put_user_permissions_boundary(
            UserName = Tenant_GeneralUserName,
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
# Create/Update/Delete Role with PB
#----------------------------------
# Create Role
def chek_create_role_with_pb(session, debug):
    try:
        Title  = 'No3.Verify that creating a role with the General PB successes.'
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
                    "Principal": { "Service": [ "lambda.amazonaws.com"] }
                }
            ]
        }
        ret = session.client('iam').create_role(
            RoleName = 'Tenant-Dummy-Role',
            AssumeRolePolicyDocument = json.dumps(assume),
            PermissionsBoundary      = 'arn:aws:iam::{}:policy/{}'.format( accountid,PB_GeneralPolicyName )
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

# update Role-1
def chek_update_role_with_pb(session, debug):
    try:
        Title  = 'No3.Verify that updating a role with the General PB successes(MAX Session).'
        result = ret_failed
        ret = None

        ident = session.client('sts').get_caller_identity()
        accountid = ident['Account']

        ret = session.client('iam').update_role(
            RoleName = 'Tenant-Dummy-Role',
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
def chek_update_description_role_with_pb(session, debug):
    try:
        Title  = 'No3.Verify that updating a role description with the General PB successes.'
        result = ret_failed
        ret = None

        ident = session.client('sts').get_caller_identity()
        accountid = ident['Account']

        ret = session.client('iam').update_role_description(
            RoleName = 'Tenant-Dummy-Role',
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
def chek_update_assumerole_role_with_pb(session, debug):
    try:
        Title  = 'No3.Verify that updating assume role at the role with the General PB successes.'
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
            RoleName = 'Tenant-Dummy-Role',
            PolicyDocument = json.dumps(assume)
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
def check_add_managed_policy_to_role(session, debug):
    try:
        Title  = 'No3.Verify that adding a managed policy to a role successes.'
        result = ret_failed
        ret = None

        ret = session.client('iam').attach_role_policy(
            RoleName  = 'Tenant-Dummy-Role',
            PolicyArn = 'arn:aws:iam::aws:policy/AdministratorAccess'
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

# delete managed policy
def check_delete_managed_policy_to_role(session, debug):
    try:
        Title  = 'No3.Verify that deleting a managed policy to a role successes.'
        result = ret_failed
        ret = None

        ret = session.client('iam').detach_role_policy(
            RoleName  = 'Tenant-Dummy-Role',
            PolicyArn = 'arn:aws:iam::aws:policy/AdministratorAccess'
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

# add inline policy
def check_add_inline_policy_to_role(session, debug):
    try:
        Title  = 'No3.Verify that adding a inline policy to a role successes.'
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
            RoleName   = 'Tenant-Dummy-Role',
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
def check_delete_inline_policy_to_role(session, debug):
    try:
        Title  = 'No3.Verify that deleting a inline policy to a role successes.'
        result = ret_failed
        ret = None

        ret = session.client('iam').delete_role_policy(
            RoleName   = 'Tenant-Dummy-Role',
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

# delete Role
def check_delete_role(session, debug):
    try:
        Title  = 'No3.Verify that deleting a role successes.'
        result = ret_failed
        ret = None

        ret = session.client('iam').delete_role(
            RoleName = 'Tenant-Dummy-Role'
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
# Create/Delete User with PB
#----------------------------------
# Create user
def chek_create_user_with_pb(session, debug):
    try:
        Title  = 'No3.Verify that creating a user with the General PB successes.'
        result = ret_failed
        ret = None

        ident = session.client('sts').get_caller_identity()
        accountid = ident['Account']

        ret = session.client('iam').create_user(
            UserName = 'Tenant-Dummy-User',
            PermissionsBoundary = 'arn:aws:iam::{}:policy/{}'.format( accountid,PB_GeneralPolicyName )
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

# delete user
def chek_delete_user_with_pb(session, debug):
    try:
        Title  = 'No3.Verify that deleting a user with the General PB successes.'
        result = ret_failed
        ret = None

        ret = session.client('iam').delete_user(
            UserName = 'Tenant-Dummy-User'
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