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

import sys
import argparse
import json
import xxlimited
import boto3

from testlib import iam_test_common
from testlib import iam_test_admin


# ---------------------------
# Set Test Pattern
# ---------------------------
test_list =[
    {
        'Role_Name': 'Tenant-Admin-Role',
        'Test_Target': False,
        'TestItems': [
            iam_test_common.chek_deny_pb_high_authority_from_role,
            iam_test_common.chek_deny_pb_high_authority_from_user,
            iam_test_common.chek_deny_pb_general_from_role,
            iam_test_common.chek_deny_pb_general_from_user,
            iam_test_common.chek_deny_delete_pb_high_authority_policy,
            iam_test_common.chek_deny_delete_pb_general_policy,
            iam_test_common.chek_deny_create_pb_high_authority_policy_version,
            iam_test_common.chek_deny_create_pb_general_policy_version,
            iam_test_common.chek_deny_delete_pb_high_authority_policy_version,
            iam_test_common.chek_deny_delete_pb_general_policy_version,
            iam_test_admin.chek_deny_create_role_without_pb,
            iam_test_admin.chek_deny_create_user_without_pb,
            iam_test_admin.chek_deny_change_pb_of_general_role,
            iam_test_admin.chek_deny_change_pb_of_general_user,
            iam_test_admin.chek_create_role_with_pb,
            iam_test_admin.chek_update_role_with_pb,
            iam_test_admin.chek_update_description_role_with_pb,
            iam_test_admin.chek_update_assumerole_role_with_pb,
            iam_test_admin.check_add_managed_policy_to_role,
            iam_test_admin.check_delete_managed_policy_to_role,
            iam_test_admin.check_add_inline_policy_to_role,
            iam_test_admin.check_delete_inline_policy_to_role,
            iam_test_admin.check_delete_role,
            iam_test_admin.chek_create_user_with_pb,
            iam_test_admin.chek_delete_user_with_pb,
            iam_test_common.check_delete_ccoe_role,
            iam_test_common.chek_update_ccoe_role,
            iam_test_common.chek_update_description_ccoe_role,
            iam_test_common.chek_update_assumerole_ccoe_role,
            iam_test_common.check_add_managed_policy_to_ccoe_role,
            iam_test_common.check_delete_managed_policy_to_ccoe_role,
            iam_test_common.check_add_inline_policy_to_ccoe_role,
            iam_test_common.check_delete_inline_policy_to_ccoe_role,
            iam_test_common.chek_change_pb_of_ccoe_role,
            iam_test_common.chek_delete_ccoe_user,
            iam_test_common.chek_attach_pb_to_ccoe_user,
            iam_test_common.check_add_managed_policy_to_ccoe_user,
            iam_test_common.check_delete_managed_policy_to_ccoe_user,
            iam_test_common.check_add_inline_policy_to_ccoe_user,
            iam_test_common.check_delete_inline_policy_to_ccoe_user,
            iam_test_common.check_create_login_passwd_to_ccoe_user,
            iam_test_common.check_update_login_passwd_to_ccoe_user,
            iam_test_common.check_delete_login_passwd_to_ccoe_user,
            iam_test_common.check_create_access_key_to_ccoe_user,
            iam_test_common.check_update_access_key_to_ccoe_user,
            iam_test_common.check_delete_access_key_to_ccoe_user,
            iam_test_common.check_enable_mfa_device_to_ccoe_user,
            iam_test_common.check_enable_mfa_device_to_ccoe_user,
            iam_test_common.check_enable_mfa_device_to_ccoe_user,
            iam_test_common.chek_delete_ccoe_group,
            iam_test_common.chek_update_ccoe_group,
            iam_test_common.chek_add_user_to_ccoe_group,
            iam_test_common.chek_remove_user_from_ccoe_group,
            iam_test_common.check_add_managed_policy_to_ccoe_group,
            iam_test_common.check_delete_managed_policy_to_ccoe_group,
            iam_test_common.check_add_inline_policy_to_ccoe_group,
            iam_test_common.check_delete_inline_policy_to_ccoe_group
        ]
    },
    {
        'Role_Name': 'Tenant-General-Role',
        'Test_Target': True,
        'TestItems': [
            iam_test_common.chek_deny_pb_high_authority_from_role,
            iam_test_common.chek_deny_pb_high_authority_from_user,
            iam_test_common.chek_deny_pb_general_from_role,
            iam_test_common.chek_deny_pb_general_from_user,
            iam_test_common.chek_deny_delete_pb_high_authority_policy,
            iam_test_common.chek_deny_delete_pb_general_policy,
            iam_test_common.chek_deny_create_pb_high_authority_policy_version,
            iam_test_common.chek_deny_create_pb_general_policy_version,
            iam_test_common.chek_deny_delete_pb_high_authority_policy_version,
            iam_test_common.chek_deny_delete_pb_general_policy_version,
            #iam_test_admin.chek_deny_create_role_without_pb,
            #iam_test_admin.chek_deny_create_user_without_pb,
            #iam_test_admin.chek_deny_change_pb_of_general_role,
            #iam_test_admin.chek_deny_change_pb_of_general_user,
            #iam_test_admin.chek_create_role_with_pb,
            #iam_test_admin.chek_update_role_with_pb,
            #iam_test_admin.chek_update_description_role_with_pb,
            #iam_test_admin.chek_update_assumerole_role_with_pb,
            #iam_test_admin.check_add_managed_policy_to_role,
            #iam_test_admin.check_delete_managed_policy_to_role,
            #iam_test_admin.check_add_inline_policy_to_role,
            #iam_test_admin.check_delete_inline_policy_to_role,
            #iam_test_admin.check_delete_role,
            #iam_test_admin.chek_create_user_with_pb,
            #iam_test_admin.chek_delete_user_with_pb,
            iam_test_common.check_delete_ccoe_role,
            iam_test_common.chek_update_ccoe_role,
            iam_test_common.chek_update_description_ccoe_role,
            iam_test_common.chek_update_assumerole_ccoe_role,
            iam_test_common.check_add_managed_policy_to_ccoe_role,
            iam_test_common.check_delete_managed_policy_to_ccoe_role,
            iam_test_common.check_add_inline_policy_to_ccoe_role,
            iam_test_common.check_delete_inline_policy_to_ccoe_role,
            iam_test_common.chek_change_pb_of_ccoe_role,
            iam_test_common.chek_delete_ccoe_user,
            iam_test_common.chek_attach_pb_to_ccoe_user,
            iam_test_common.check_add_managed_policy_to_ccoe_user,
            iam_test_common.check_delete_managed_policy_to_ccoe_user,
            iam_test_common.check_add_inline_policy_to_ccoe_user,
            iam_test_common.check_delete_inline_policy_to_ccoe_user,
            iam_test_common.check_create_login_passwd_to_ccoe_user,
            iam_test_common.check_update_login_passwd_to_ccoe_user,
            iam_test_common.check_delete_login_passwd_to_ccoe_user,
            iam_test_common.check_create_access_key_to_ccoe_user,
            iam_test_common.check_update_access_key_to_ccoe_user,
            iam_test_common.check_delete_access_key_to_ccoe_user,
            iam_test_common.check_enable_mfa_device_to_ccoe_user,
            iam_test_common.check_enable_mfa_device_to_ccoe_user,
            iam_test_common.check_enable_mfa_device_to_ccoe_user,
            iam_test_common.chek_delete_ccoe_group,
            iam_test_common.chek_update_ccoe_group,
            iam_test_common.chek_add_user_to_ccoe_group,
            iam_test_common.chek_remove_user_from_ccoe_group,
            iam_test_common.check_add_managed_policy_to_ccoe_group,
            iam_test_common.check_delete_managed_policy_to_ccoe_group,
            iam_test_common.check_add_inline_policy_to_ccoe_group,
            iam_test_common.check_delete_inline_policy_to_ccoe_group
        ]
    }
]





# ---------------------------
# Initialize Section
# ---------------------------
def get_args():
    parser = argparse.ArgumentParser(
        description='Test tool')

    parser.add_argument(
        '-d', '--debug',
        action='store_true',
        default=False,
        required=False,
        help='Enable debug mode.'
    )

    parser.add_argument(
        '-p', '--profile',
        action   = 'store',
        default  = 'default',
        type     = str,
        required = False,
        help     = 'Specify profile.'
    )

    return( parser.parse_args() )


# ---------------------------
def assume_role(profile, role_name):
    session = boto3.session.Session(
        profile_name = profile
    )
    # Get Role ARN
    ret = session.client('iam').get_role(
        RoleName = role_name
    )
    role_arn = ret['Role']['Arn']
    
    # Assume Role
    credential = session.client('sts').assume_role(
        RoleArn = role_arn,
        RoleSessionName = 'PBTest' 
    )

    assume_role_session = boto3.session.Session(
        aws_access_key_id     = credential['Credentials']['AccessKeyId'],
        aws_secret_access_key = credential['Credentials']['SecretAccessKey'],
        aws_session_token     = credential['Credentials']['SessionToken'],
    )

    return( assume_role_session )


# ---------------------------
# Main function
# ---------------------------
def main():

    # Initialize
    args = get_args()

    # Test
    total_OK = 0
    total_NG = 0
    total_Failed = 0
    for target in test_list:
        if target['Test_Target']:
            print('<<<<<<<< Target Role => {} >>>>>>>>>>>>>\n'.format(target['Role_Name']))

            # Assume Role
            session = assume_role(
                profile   = args.profile,
                role_name = target['Role_Name']
            )
            if args.debug:
                    print('Session----------------\n')
                    json.dump(
                        session.client('sts').get_caller_identity(),
                        sys.stdout,
                        ensure_ascii=False,
                        indent=2
                    )
                    print('-----------------------\n')

            #Test
            count  = 1
            OK     = 0
            NG     = 0
            Failed = 0
            for item in target['TestItems']:
                ret = item(session = session, debug = args.debug)
                print( '#{:2d} {:100s} :ret = {:s}'.format(count, ret['Title'],ret['Result']) )
                if ret['Result'] == 'OK':
                    OK += 1
                elif ret['Result'] == 'NG':
                    NG += 1
                elif ret['Result'] == 'Failed':
                    Failed += 1
                else:
                    print('invalid error: ret={}\n'.format(ret['Result']))
                count += 1

            print('Result: OK:{}  NG:{}  Failed:{}\n\n'.format(OK, NG, Failed))
            total_OK     += OK
            total_NG     += NG
            total_Failed += Failed
        
    #Total result
    print('Total Result: total_OK:{}  total_NG:{}  total_Failed:{}\n'.format(total_OK, total_NG, total_Failed))

if __name__ == "__main__":
    sys.exit(main())