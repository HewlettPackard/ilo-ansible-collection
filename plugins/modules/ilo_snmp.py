#!/usr/bin/env python
# -*- coding: utf-8 -*-
###
# Copyright (2016-2024) Hewlett Packard Enterprise Development LP
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

DOCUMENTATION = """
---
module: ilo_snmp
short_description: Performs SNMP related operations on iLO using Redfish APIs
version_added: 4.2.0
description:
  - Builds Redfish URIs locally and sends them to iLO to
    perform SNMP related operations.
  - For use with HPE iLO SNMP operations that require Redfish OEM extensions.
options:
  category:
    required: true
    description:
      - List of categories to execute on iLO.
    type: list
    elements: str
  command:
    required: true
    description:
      - List of commands to execute on iLO.
    type: list
    elements: str
  baseuri:
    required: true
    description:
      - Base URI of iLO.
    type: str
  username:
    description:
      - User for authentication with iLO.
    type: str
  password:
    description:
      - Password for authentication with iLO.
    type: str
  auth_token:
    description:
      - Security token for authentication with iLO.
    type: str
    version_added: 2.3.0
  timeout:
    description:
      - Timeout in seconds for URL requests to iLO.
    default: 60
    type: int
  cert_file:
    description:
      - absolute path to the server cert file
    type: str
  key_file:
    description:
      - absolute path to the server key file
    type: str
  snmpv3_users:
    description:
      - List of SNMPv3 users that needs to be added in the given server
    type: list
    elements: dict
    suboptions:
      security_name:
        required: true
        description:
          - SNMPv3 security name associated with SNMPv3trap or SNMPv3Inform set on SNMPAlertProtocol
          - Alphanumeric value with 1-32 characters
        type: str
      auth_protocol:
        required: true
        description:
          - Sets the message digest algorithm to use for encoding the authorization passphrase
          - The message digest is calculated over an appropriate portion of an SNMP message and is included as part of the message sent to the recipient
          - Supported Auth protocols are MD5, SHA, and SHA256
        type: str
      auth_passphrase:
        required: true
        description:
          - Sets the passphrase to use for sign operations
          - String with 8-49 characters
        type: str
      privacy_protocol:
        required: true
        description:
          - Sets the encryption algorithm to use for encoding the privacy passphrase
          - A portion of an SNMP message is encrypted before transmission
          - Supported privacy protocols are AES and DES
        type: str
      privacy_passphrase:
        required: true
        description:
          - Sets the passphrase to use for encrypt operations
          - String with 8-49 characters
        type: str
      user_engine_id:
        required: true
        description:
          - The SNMPv3 Engine ID is the unique identifier of an SNMP engine that belongs to an SNMP agent entity
          - This value must be a hexadecimal string with an even number of 10 to 64 characters, excluding first two characters, 0x (example 0x01020304abcdef)
        type: str
  alert_destinations:
    description:
      - List of alert destination that needs to be added in the given server
    type: list
    elements: dict
    suboptions:
      alert_destination:
        required: true
        description:
          - IP address/hostname/FQDN of remote management system that receives SNMP alerts
        type: str
      snmp_alert_protocol:
        required: true
        description:
          - SNMP protocol associated with the AlertDestination
          - The supported SNMP alert protocols are SNMPv1Trap, SNMPv3Trap, and SNMPv3Inform
        type: str
      trap_community:
        required: true
        description:
          - Configuring trap community string
          - This option is supported for SNMPv1Trap, SNMPv3Trap, and SNMPv3Inform alert protocols
        type: str
  snmpv3_usernames:
    description:
      - List of SNMPv3 user names that need to be deleted from the given server
    type: list
    elements: str
author:
  - Gayathiri Devi Ramasamy (@Gayathirideviramasamy)
  - T S Kushal (@TSKushal)
  - Varni H P (@varini-hp)
  - Prativa Nayak (@prativa-n)
  - Nagendra M (@nagendram399)
"""

EXAMPLES = """
  - name: Get SNMP V3 Users
    ilo_snmp:
      category: Manager
      command: GetSnmpV3Users
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"

  - name: Get SNMP alert destinations
    ilo_snmp:
      category: Manager
      command: GetSnmpAlertDestinations
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"

  - name: Deleting all the SNMPv3 users
    ilo_snmp:
      category: Manager
      command: DeleteAllSNMPv3Users
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"

  - name: Deleting specified SNMPv3 users
    ilo_snmp:
      category: Manager
      command: DeleteSpecifiedSNMPv3Users
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"
      snmpv3_usernames:
        - user1
        - user2

  - name: Deleting all the SNMP alert destinations
    ilo_snmp:
      category: Manager
      command: DeleteAllSNMPAlertDestinations
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"

  - name: Updating specified SNMPv3 users
    ilo_snmp:
      category: Manager
      command: UpdateSNMPv3Users
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"
      snmpv3_users:
        - security_name: "Sec1"
          auth_protocol: "SHA"
          auth_passphrase: "********"
          privacy_protocol: "AES"
          privacy_passphrase: "********"
          user_engine_id: "123450abdcef"

  - name: Creating SNMPv3 users
    ilo_snmp:
      category: Manager
      command: CreateSNMPv3Users
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"
      snmpv3_users:
        - security_name: "Sec1"
          auth_protocol: "SHA"
          auth_passphrase: "********"
          privacy_protocol: "AES"
          privacy_passphrase: "********"
          user_engine_id: "123450abdcef"

  - name: Creating SNMP alert destinations
    ilo_snmp:
      category: Manager
      command: CreateSNMPAlertDestinations
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"
      alert_destinations:
        - snmp_alert_protocol: "SNMPv1Trap"
          trap_community: "public"
          alert_destination: "************"
          security_name: "Sec1"
"""

RETURN = """
ilo_snmp:
    description: Returns the status of the operation performed on the iLO.
    type: dict
    contains:
        command:
            description: Returns the output msg and whether the function executed successfully.
            type: dict
            contains:
                ret:
                    description: Return True/False based on whether the operation was performed succesfully.
                    type: bool
                msg:
                    description: Status of the operation performed on the iLO.
                    type: dict
    returned: always
"""

CATEGORY_COMMANDS_ALL = {
    "Manager": ["GetSNMPv3Users",
                "GetSNMPAlertDestinations",
                "DeleteAllSNMPv3Users",
                "DeleteSpecifiedSNMPv3Users",
                "DeleteAllSNMPAlertDestinations",
                "UpdateSNMPv3Users",
                "CreateSNMPv3Users",
                "CreateSNMPAlertDestinations"]}

CATEGORY_COMMANDS_DEFAULT = {
    "Manager": "GetSNMPv3Users"
}

HAS_OEM_REDFISH = True

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
try:
    from ansible_collections.hpe.ilo.plugins.module_utils.ilo_oem_utils import iLOOemUtils, ilo_certificate_login
except ImportError:
    OEM_REDFISH_IMP_ERR = traceback.format_exc()
    HAS_OEM_REDFISH = False


def main():
    result = {}
    category_list = []
    module = AnsibleModule(
        argument_spec=dict(
            category=dict(required=True, type="list", elements="str"),
            command=dict(required=True, type="list", elements="str"),
            baseuri=dict(required=True),
            username=dict(),
            password=dict(no_log=True),
            auth_token=dict(no_log=True),
            timeout=dict(type="int", default=60),
            cert_file=dict(type="str"),
            key_file=dict(type="str"),
            snmpv3_usernames=dict(type='list', elements='str'),
            snmpv3_users=dict(type='list', elements='dict'),
            alert_destinations=dict(type='list', elements='dict')
        ),
        required_together=[
            ("username", "password"),
            ("cert_file", "key_file")
        ],
        required_one_of=[
            ("username", "auth_token", "cert_file"),
        ],
        mutually_exclusive=[
            ("username", 'auth_token', 'cert_file'),
        ],
        supports_check_mode=True
    )

    creds = {
        "user": module.params["username"],
        "pswd": module.params["password"],
        "token": module.params["auth_token"],
    }

    if not HAS_OEM_REDFISH:
        module.fail_json(msg="missing required fucntions in ilo_oem_utils.py")

    timeout = module.params["timeout"]

    root_uri = "https://" + module.params["baseuri"]

    if module.params["cert_file"]:
        creds["token"] = ilo_certificate_login(root_uri, module, module.params["cert_file"], module.params["key_file"])

    rf_utils = iLOOemUtils(creds, root_uri, timeout, module)

    # Build Category list
    if "all" in module.params["category"]:
        for entry in CATEGORY_COMMANDS_ALL:
            category_list.append(entry)
    else:
        # one or more categories specified
        category_list = module.params["category"]

    for category in category_list:
        command_list = []
        # Build Command list for each Category
        if category in CATEGORY_COMMANDS_ALL:
            if not module.params["command"]:
                # True if we don't specify a command --> use default
                command_list.append(CATEGORY_COMMANDS_DEFAULT[category])
            elif "all" in module.params["command"]:
                for entry in CATEGORY_COMMANDS_ALL[category]:
                    command_list.append(entry)
            # one or more commands
            else:
                command_list = module.params["command"]
                # Verify that all commands are valid
                for cmd in command_list:
                    # Fail if even one command given is invalid
                    if cmd not in CATEGORY_COMMANDS_ALL[category]:
                        module.fail_json(msg="Invalid Command: %s" % cmd)
        else:
            # Fail if even one category given is invalid
            module.fail_json(msg="Invalid Category: %s" % category)

        # Organize by Categories / Commands
        if category == "Manager":
            resource = rf_utils._find_managers_resource()
            if resource['ret'] is False:
                module.fail_json(msg=resource['msg'])

            for command in command_list:
                if command == "GetSNMPv3Users":
                    result[command] = rf_utils.get_snmpv3_users()
                elif command == "GetSNMPAlertDestinations":
                    result[command] = rf_utils.get_snmp_alert_destinations()
                elif command == "DeleteAllSNMPv3Users":
                    result[command] = rf_utils.delete_all_snmpv3_users()
                elif command == "DeleteAllSNMPAlertDestinations":
                    result[command] = rf_utils.delete_all_snmp_alert_destinations()
                elif command == "DeleteSpecifiedSNMPv3Users":
                    result[command] = rf_utils.delete_snmpv3_users(module.params['snmpv3_usernames'])
                elif command == "UpdateSNMPv3Users":
                    result[command] = rf_utils.update_snmpv3_users(module.params['snmpv3_users'])
                elif command == "CreateSNMPv3Users":
                    result[command] = rf_utils.create_snmpv3_users(module.params['snmpv3_users'])
                elif command == "CreateSNMPAlertDestinations":
                    result[command] = rf_utils.create_alert_destinations(module.params['alert_destinations'])

    if not result[command]['ret']:
        module.fail_json(msg=to_native(result))

    module.exit_json(ilo_snmp=result)


if __name__ == "__main__":
    main()
