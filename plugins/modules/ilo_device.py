#!/usr/bin/python
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
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
import traceback

__metaclass__ = type

DOCUMENTATION = """
---
module: ilo_device
short_description: Performs Device related operations on iLO using Redfish APIs
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
author:
  - Gayathiri Devi Ramasamy (@Gayathirideviramasamy)
  - T S Kushal (@TSKushal)
  - Varni H P (@varini-hp)
  - Prativa Nayak (@prativa-n)
  - Nagendra M (@nagendram399)
"""

EXAMPLES = """
  - name: Get Device Inventory Information
    ilo_device:
      category: Chassis
      command: GetDeviceInventoryInfo
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"
"""

RETURN = """
ilo_device:
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

CATEGORY_COMMANDS_ALL = {"Chassis": [
    "GetDeviceInventoryInfo", "IndicatorLedOff", "IndicatorLedOn", "IndicatorLedBlink"]}

CATEGORY_COMMANDS_DEFAULT = {"Chassis": "GetDeviceInventoryInfo"}

HAS_OEM_REDFISH = True

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
            key_file=dict(type="str")
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
        if category == "Chassis":
            for command in command_list:
                result[command] = {}
                if command == "GetDeviceInventoryInfo":
                    result[command] = rf_utils.get_device_inventory_info()

                if command in ["IndicatorLedOff", "IndicatorLedOn", "IndicatorLedBlink"]:
                    result[command] = rf_utils._find_chassis_resource()
                    if result[command]['ret'] is False:
                        module.fail_json(msg=to_native(result['msg']))
                    LED_commands = ["IndicatorLedOff",
                                    "IndicatorLedOn", "IndicatorLedBlink"]
                    no_of_commands = sum(
                        [command in LED_commands for command in command_list])
                    if no_of_commands > 1:
                        result[command] = {
                            'ret': False, 'msg': "Only one IndicatorLed command should be sent at a time."}
                    else:
                        response = rf_utils.get_request(
                            root_uri + "/redfish/v1/Managers/1")
                        if response['ret'] is False:
                            module.fail_json(msg=to_native(response))
                        version = float(response['data']['FirmwareVersion'][4] + "." + response['data']
                                        ['FirmwareVersion'][7] + response['data']['FirmwareVersion'][9:11])
                        if version < 6:
                            result[command] = rf_utils.manage_chassis_indicator_led(
                                command)
                        else:
                            if command == "IndicatorLedBlink":
                                result[command] = {
                                    'ret': False, 'msg': "This option is not avaible for iLO 6."}
                            else:
                                result[command] = rf_utils.manage_chassis_ilo6_led(
                                    command)

    if not result[command]['ret']:
        module.fail_json(msg=to_native(result))

    module.exit_json(ilo_device=result)


if __name__ == "__main__":
    main()
