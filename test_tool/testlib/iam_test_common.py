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


        