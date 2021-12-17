#!/usr/bin/python
# -*- coding: utf-8 -*-
###
# Copyright (2021) Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###
from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: create_snmpv3_users
description: This module creates SNMPv3 users in a server
requirements:
    - "python >= 3.6"
    - "ansible >= 2.11"
author:
    - "Gayathiri Devi Ramasamy (@Gayathirideviramasamy)"
options:
  baseuri:
    description:
      - iLO IP of the server
    type: str
    default: NONE
    required: true
  username:
    description:
      - Username of the server for authentication
    type: str
    default: NONE
    required: true
  password:
    description:
      - Password of the server for authentication
    type: str
    default: NONE
    required: true
  snmpv3_users:
    description:
      - List of SNMPv3 users that needs to be added in the given server
    type: list
    default: NONE
    required: true
  security_name:
    description:
      - SNMPv3 security name associated with SNMPv3trap or SNMPv3Inform set on SNMPAlertProtocol
      - Alphanumeric value with 1-32 characters
    type: str
    default: NONE
    required: true
  auth_protocol:
    description:
      - Sets the message digest algorithm to use for encoding the authorization passphrase
      - The message digest is calculated over an appropriate portion of an SNMP message and is included as part of the message sent to the recipient
      - Supported Auth protocols are MD5, SHA, and SHA256
    type: str
    default: NONE
    required: true
  auth_passphrase:
    description:
      - Sets the passphrase to use for sign operations
      - String with 8-49 characters
    type: str
    default: NONE
    required: true
  privacy_protocol:
    description:
      - Sets the encryption algorithm to use for encoding the privacy passphrase
      - A portion of an SNMP message is encrypted before transmission
      - Supported privacy protocols are AES and DES
    type: str
    default: NONE
    required: true
  privacy_passphrase:
    description:
      - Sets the passphrase to use for encrypt operations
      - String with 8-49 characters
    type: str
    default: NONE
    required: true
  http_schema:
    description:
      - http or https Protocol
    type: str
    default: https
    required: false
"""

EXAMPLES = r"""
- name: Creating SNMPv3 users
  create_snmpv3_users:
    baseuri:  "***.***.***.***"
    username: "abcxyz"
    password: "******"
    snmpv3_users:
      - security_name: "Sec1"
        auth_protocol: "SHA"
        auth_passphrase: "********"
        privacy_protocol: "AES"
        privacy_passphrase: "********"
"""

RETURN = r"""
  expected_result:
    description: SNMPv3 users are created in the server
    returned: SNMPv3 users are added
    type: str
  failure case 1:
    description: Redfish Package is not installed
    returned: Failed to import the required Python library (redfish)
    corrective_action: Install python3-redfish package
    type: str
  failure case 2:
    description: Incorrect/Unreachable server IP address(baseuri) is provided
    returned: RetriesExhaustedError
    corrective_action: Provide the correct IP address of the server
    type: str
  failure case 3:
    description: Credentials not valid
    returned: InvalidCredentialsError
    corrective_action: Validate the credentials
    type: str
  failure case 4:
    description: Getting managers data failed
    returned: GET on /redfish/v1/Managers/1/ Failed, Status <Status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 5:
    description: Getting list of SNMPv3 users failed
    returned: GET on /redfish/v1/Managers/1/SnmpService/SNMPUsers/ Failed, Status <Status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 6:
    description: Getting particular SNMPv3 user failed
    returned: GET on /redfish/v1/Managers/1/SnmpService/SNMPUsers/<SNMPv3 user ID>/ Failed, Status <Status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 7:
    description: Maximum snmpv3 users in the server reached
    returned: Maximum of 8 SNMPv3 users can be added to a server. Already server has <number of existing users in server> users and provided <number of users provided as input> more users
    corrective_action: Expected output if maximum limit of snmpv3 users reached. Validate the input to provide the correct number of snmpv3 users
    type: str
  failure case 8:
    description: Input parameter is missing
    returned: Input parameter <list of parameters> is missing to create SNMPv3 user. Mandatory parameters are <List of input parameters>
    corrective_action: Validate the input parameters
    type: str
  failure case 9:
    description: Wrong protocol provided
    returned: Given value <protocol type> is not supported for <protocol>
    corrective_action: Validate the input parameters
    type: str
  failure case 10:
    description: auth_passphrase & privacy_passphrase minimum length not satisfied
    returned: Minimum character length for auth_passphrase & privacy_passphrase is 8
    corrective_action: Validate the input values for auth_passphrase & privacy_passphrase
    type: str
  failure case 11:
    description: User exists with same name and different protocols
    returned: Already user exists with same name <security name> and protocols <auth_protocol and privacy_protocol>, so user cannot be created with different protocols
    corrective_action: Modify the security name or delete the existing user
    type: str
  failure case 12:
    description: User exists with same name and protocols
    returned: Already user exists with same name <security name> and same protocols <auth_protocol and privacy_protocol>
    corrective_action: Modify the security name
    type: str
  failure case 13:
    description: Adding SNMPv3 user failed
    returned: Adding SNMPv3 user <SNMPv3 username> failed, Status <Status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 14:
    description: Value for security_name is empty
    returned: security_name should not be empty
    corrective_action: Provide value for security name(user name)
    type: str
  failure case 15:
    description: Wrong input parameter is provided
    returned: Unsupported input parameters <list of input parameters>
    corrective_action: Remove wrong parameters from the input
    type: str
  failure case 16:
    description: Duplicate entry is provided
    returned: Duplicate entries provided for users <list of duplicate users>
    corrective_action: Remove duplicate entries from the input
    type: str
"""

import json

try:
    from redfish import redfish_client

    HAS_REDFISH = True
except ImportError:
    HAS_REDFISH = False

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

base_uri = "/redfish/v1/"
manager_uri = "Managers/1/"


def logout(redfishClient, module):
    redfishClient.logout()


def error_msg(module, method, uri, status, response):
    # Print error message
    module.fail_json(
        msg="%s on %s Failed, Status: %s, Response: %s"
        % (str(method), str(uri), str(status), str(response))
    )


def get_snmpv3_users(redfishClient, module):
    # Get on Managers API
    snmpv3_users = []
    uri = base_uri + manager_uri
    response = redfishClient.get(uri)
    if response.status != 200:
        error_msg(module, "GET", uri, response.status, response.text)
    snmp_res = redfishClient.get(uri + "SnmpService/SNMPUsers/")
    if snmp_res.status != 200:
        error_msg(
            module,
            "GET",
            uri + "SnmpService/SNMPUsers/",
            snmp_res.status,
            snmp_res.text,
        )
    snmp_list = json.loads(snmp_res.text)
    for item in snmp_list["Members"]:
        item_rsp = redfishClient.get(item["@odata.id"])
        if item_rsp.status != 200:
            error_msg(module, "GET", item["@odata.id"], item_rsp.status, item_rsp.text)
        snmpv3_users.append(json.loads(item_rsp.text))
    return snmpv3_users


def validate_duplicate_entries(snmpv3_users, module):
    # Validating duplicate entry
    duplicate = []
    snmpv3_user_names = [i["security_name"] for i in snmpv3_users]
    for snmp in snmpv3_user_names:
        if snmpv3_user_names.count(snmp) > 1:
            duplicate.append(snmp)
    if duplicate:
        module.fail_json(
            msg="Duplicate entries provided for users: %s" % str(list(set(duplicate)))
        )


def validate_snmpv3_users(server_snmpv3_users, snmpv3_users, module):
    # Validating input parameters
    if len(server_snmpv3_users) + len(snmpv3_users) > 8:
        message = (
            "Maximum of 8 SNMPv3 users can be added to a server..."
            + "Already server has %s users and provided %s more users"
        )
        module.fail_json(msg=message % (len(server_snmpv3_users), len(snmpv3_users)))

    input_list = [
        "security_name",
        "auth_protocol",
        "auth_passphrase",
        "privacy_protocol",
        "privacy_passphrase",
    ]
    validate_dict = {
        "auth_protocol": ["MD5", "SHA", "SHA256"],
        "privacy_protocol": ["DES", "AES"],
    }

    for user in snmpv3_users:
        missing_param = []
        for input in input_list:
            if input not in user.keys():
                missing_param.append(input)
        if missing_param:
            module.fail_json(
                msg="Input parameter %s is missing to create SNMPv3 user. Mandatory parameters are %s"
                % (str(missing_param), str(input_list))
            )

        if not user["security_name"]:
            module.fail_json(msg="'security_name' should not be empty")

        for key, value in validate_dict.items():
            if user[key] not in value:
                module.fail_json(
                    "Given value '%s' is not supported for '%s'" % (user[key], key)
                )

        if not (
            len(user["privacy_passphrase"]) >= 8 and len(user["auth_passphrase"]) >= 8
        ):
            module.fail_json(
                msg="Minimum character length for auth_passphrase & privacy_passphrase is 8"
            )

        if set(user.keys()) - set(input_list):
            module.fail_json(
                msg="Unsupported input parameters: %s"
                % str(list(set(user.keys()) - set(input_list)))
            )


def check_snmpv3_users(server_snmpv3_users, snmpv3_users, module):
    # Validating if SNMPv3 users already exists
    for user in snmpv3_users:
        for data in server_snmpv3_users:
            if data["SecurityName"] == user["security_name"]:
                if (
                    data["AuthProtocol"] != user["auth_protocol"]
                    or data["PrivacyProtocol"] != user["privacy_protocol"]
                ):
                    message = (
                        "Already user exists with same name '%s' and protocols "
                        + "AuthProtocol: '%s' and PrivacyProtocol: '%s'. "
                        + "so user cannot be created with different protocols..."
                    )
                    module.fail_json(
                        msg=message
                        % (
                            data["SecurityName"],
                            data["AuthProtocol"],
                            data["PrivacyProtocol"],
                        )
                    )
                else:
                    message = (
                        "Already user exists with same name '%s' and same protocols "
                        + "AuthProtocol: '%s' and PrivacyProtocol: '%s'."
                    )
                    module.fail_json(
                        msg=message
                        % (
                            data["SecurityName"],
                            data["AuthProtocol"],
                            data["PrivacyProtocol"],
                        )
                    )


def create_snmpv3_user(redfishClient, user, module):
    # Define payload
    body = {
        "SecurityName": user["security_name"],
        "AuthProtocol": user["auth_protocol"],
        "AuthPassphrase": user["auth_passphrase"],
        "PrivacyProtocol": user["privacy_protocol"],
        "PrivacyPassphrase": user["privacy_passphrase"],
    }
    # POST on Managers API
    uri = base_uri + manager_uri + "SnmpService/SNMPUsers/"
    snmp_res = redfishClient.post(uri, body=body)
    if snmp_res.status != 201:
        module.fail_json(
            msg="Adding SNMPv3 user %s failed, status: %s, response: %s, API: %s"
            % (user["security_name"], str(snmp_res.status), snmp_res.text, uri)
        )


def main():
    module = AnsibleModule(
        argument_spec=dict(
            baseuri=dict(required=True, type="str"),
            username=dict(required=True, type="str"),
            password=dict(required=True, type="str", no_log=True),
            snmpv3_users=dict(required=True, type="list"),
            http_schema=dict(required=False, default="https", type="str"),
        )
    )

    if not HAS_REDFISH:
        module.fail_json(msg=missing_required_lib("redfish"))

    baseuri = module.params["baseuri"]
    username = module.params["username"]
    password = module.params["password"]
    snmpv3_users = module.params["snmpv3_users"]
    http_schema = module.params["http_schema"]

    base_url = "{}://{}".format(http_schema, baseuri)
    redfishClient = redfish_client(
        base_url=base_url, username=username, password=password
    )
    redfishClient.login()

    validate_duplicate_entries(snmpv3_users, module)
    server_snmpv3_users = get_snmpv3_users(redfishClient, module)
    validate_snmpv3_users(server_snmpv3_users, snmpv3_users, module)
    check_snmpv3_users(server_snmpv3_users, snmpv3_users, module)
    for user in snmpv3_users:
        create_snmpv3_user(redfishClient, user, module)

    logout(redfishClient, module)
    module.exit_json(changed=True, msg="SNMPv3 users are added")


if __name__ == "__main__":
    main()
