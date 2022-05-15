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

import sys
import argparse
import json
import xxlimited
import boto3

from testlib import iam_test


# ---------------------------
# Set Test Pattern
# ---------------------------
test_list =[
    {
        'Role_Name': 'CCoE-Admin-Role',
        'Test_Items': [
            {
                'Title': 'Check that Permissions Boundary cannot be deleted',
                'pointa': iam_test.hoge,
                'return': '200'
            }
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
    for target in test_list:
        # Assume Role
        session = assume_role(
            profile   = args.profile,
            role_name = target['Role_Name']
        )
        if args.debug:
                json.dump(
                    session.client('sts').get_caller_identity(),
                    sys.stdout,
                    ensure_ascii=False,
                    indent=2
                )


if __name__ == "__main__":
    sys.exit(main())