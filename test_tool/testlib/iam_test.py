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
PB_HighAuthorityPolicyName = 'PB-HighAuthority-Policy'

#Return code
ret_failed = 'Failed'
ret_OK ='OK'
ret_NG = 'NG'

def dump_json( message ):
    json.dump(
        message,
        sys.stdout,
        ensure_ascii=False,
        indent=2
    )
    print ('\n')

def chek_deny_pb_hight_authority_from_role(session, debug):
    try:
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
        return(result)

def chek_deny_pb_hight_authority_from_user(session, debug):
    try:
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
        return(result)