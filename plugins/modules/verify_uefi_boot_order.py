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
module: verify_uefi_boot_order
description: This module will verify if the input boot order matches with the server boot order or not when BiosMode is UEFI
requirements:
    - "python >= 3.6"
    - "ansible >= 2.11"
author:
    - "Prativa Nayak (@prativa-n)"
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
  http_schema:
    description:
      - http or https Protocol
    type: str
    default: https
    required: false
  uefi_boot_order:
    description:
      - Input UEFI Boot Order
    type: list
    default: NONE
    required: true
"""

EXAMPLES = r"""
- name: Verify input Boot Order against the server boot order
  verify_uefi_boot_order:
    baseuri: "***.***.***.***"
    username: "abcxyz"
    password: "******"
    uefi_boot_order: ["NIC.FlexLOM.1.1.IPv4"]
"""

RETURN = r"""
  expected_result:
    description: Verified boot order
    returned: True and message "Input BootOrder matches with the server BootOrder" in case of success, otherwise False
    type: str
  failure case 1:
    description: Credentials not valid
    returned: InvalidCredentialsError
    corrective_action: Validate the credentials
    type: str
  failure case 2:
    description: Getting server data failed
    returned: GET on /redfish/v1/systems/1/ Failed, Status <Status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 3:
    description: Getting bios URI failed
    returned: Getting BIOS URI Failed, Key Bios not found in /redfish/v1/systems/1/ response
    corrective_action: BIOS API not found in the server details returned. Verify BIOS details in the server
    type: str
  failure case 4:
    description: Getting BIOS settings failed
    returned: GET on /redfish/v1/systems/1/bios/ Failed, Status <Status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 5:
    description: Getting Boot settings failed
    returned: GET on /redfish/v1/Systems/1/bios/boot/settings/ Failed, Status <Status code>, Response <API response> (or)
     GET on /redfish/v1/Systems/1/bios/oem/hpe/boot/settings/ Failed, Status <Status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 6:
    description: Getting Boot settings URI failed
    returned: Boot settings uri not found in /redfish/v1/Systems/1/bios/ response <API response>
    corrective_action: Boot settings API not found in the BIOS details returned. Verify BIOS details in the server
    type: str
  failure case 7:
    description: Lesser number of elements in serverBootOrder than InputBootOrder
    returned: Lesser number of elements in serverBootOrder (<no. of elements in server bootorder>) than InputBootOrder (<no. of elements in input bootorder)
    corrective_action: No action needed, expected failure
    type: str
  failure case 8:
    description: Getting the boot order when BootMode is not UEFI
    returned: Server BootMode is not UEFI. Hence BootOrder can't be verified
    corrective_action: No action needed, expected failure
    type: str
  failure case 9:
    description: Input BootOrder doesn't match with Server BootOrder
    returned: Input BootOrder <input boot order> doesn't match with Server BootOrder <server boot order>
    corrective_action: No action needed, expected failure
    type: str
  failure case 10:
    description: Incorrect/Unreachable server IP address(baseuri) is provided
    returned: RetriesExhaustedError
    corrective_action: Provide the correct IP address of the server
    type: str
  failure case 11:
    description: Redfish Package is not installed
    returned: Failed to import the required Python library (redfish)
    corrective_action: Install python3-redfish package
    type: str
"""

import re
import json

try:
    from redfish import redfish_client

    HAS_REDFISH = True
except ImportError:
    HAS_REDFISH = False

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

base_uri = "/redfish/v1/"
system_uri = "systems/1/"


def logout(redfishClient, module):
    redfishClient.logout()


def error_msg(method, uri, status, response):
    # Print error message
    msg = "%s on %s Failed, Status: %s, Response: %s" % (
        str(method),
        str(uri),
        str(status),
        str(response),
    )
    return msg


# Getting Bios settings
def get_bios_attributes(redfishClient):

    # Get system details
    uri = base_uri + system_uri
    server_data = redfishClient.get(uri)
    if server_data.status != 200:
        message = error_msg("GET", uri, server_data.status, server_data.text)
        return False, message

    server_details = json.loads(server_data.text)
    if "Bios" not in server_details:
        message = "Getting BIOS URI Failed, Key 'Bios' not found in %s response: %s" % (
            uri,
            str(server_details),
        )
        return False, message

    bios_uri = server_details["Bios"]["@odata.id"]
    # GET BIOS settings
    response = redfishClient.get(bios_uri)
    if response.status != 200:
        message = error_msg("GET", bios_uri, response.status, response.text)
        return False, message
    server_bios = json.loads(response.text)

    return True, server_bios["Attributes"]["BootMode"]


# Getting network boot order
def get_network_boot_settings(redfishClient, module):
    """
    Getting network boot order

    Parameters
    ----------
    Null

    Returns
    -------
    res : returns PersistentBootConfigOrder
    """

    uri = "/redfish/v1/Systems/1/bios/boot/settings/"
    response = redfishClient.get(uri)
    if response.status == 404:
        uri = "/redfish/v1/Systems/1/bios/"
        res = redfishClient.get(uri)
        if res.status != 200:
            message = error_msg("GET", uri, res.status, res.text)
            module.fail_json(msg=message)
        if (
            "Oem" in res.dict
            and "Hpe" in res.dict["Oem"]
            and "Links" in res.dict["Oem"]["Hpe"]
            and "Boot" in res.dict["Oem"]["Hpe"]["Links"]
        ):
            uri = res.dict["Oem"]["Hpe"]["Links"]["Boot"]["@odata.id"] + "settings/"
            response = redfishClient.get(uri)
        else:
            module.fail_json(
                msg="Boot settings uri not found in %s response, %s"
                % (uri, str(res.dict))
            )
    if response.status != 200:
        message = error_msg("GET", uri, response.status, response.text)
        module.fail_json(msg=message)

    res = json.loads(response.text)
    return res["PersistentBootConfigOrder"]


# Verifies input boot order against server boot order
def verify_uefi_boot_order(redfishClient, module):
    input_boot_order = module.params["uefi_boot_order"]

    response = get_bios_attributes(redfishClient)
    if not response[0]:
        module.fail_json(msg=response[1])

    if response[1].lower() != "uefi":
        message = "Server BootMode is not UEFI. Hence BootOrder can't be verified"
        module.fail_json(msg=message)

    server_boot_order = get_network_boot_settings(redfishClient, module)

    if len(server_boot_order) < len(input_boot_order):
        message = (
            "Lesser number of elements in serverBootOrder ({}) than InputBootOrder ({})"
        )
        module.fail_json(
            msg=message.format(len(server_boot_order), len(input_boot_order))
        )

    for i in range(0, len(input_boot_order)):
        if input_boot_order[i].lower() != server_boot_order[i].lower():
            message = "Input BootOrder {} doesn't match with Server BootOrder {}"
            module.fail_json(msg=message.format(input_boot_order, server_boot_order))
    return True


def main():
    module = AnsibleModule(
        argument_spec=dict(
            baseuri=dict(required=True, type="str"),
            username=dict(required=True, type="str"),
            password=dict(required=True, type="str", no_log=True),
            uefi_boot_order=dict(required=True, type="list"),
            http_schema=dict(required=False, default="https", type="str"),
        )
    )

    if not HAS_REDFISH:
        module.fail_json(msg=missing_required_lib("redfish"))

    http_schema = module.params["http_schema"]
    base_url = "{0}://{1}".format(http_schema, module.params["baseuri"])
    redfishClient = redfish_client(
        base_url=base_url,
        username=module.params["username"],
        password=module.params["password"],
    )
    redfishClient.login()

    result = {}

    result["boot_verification_status"] = verify_uefi_boot_order(redfishClient, module)
    result["message"] = "Input BootOrder matches with the server BootOrder"

    logout(redfishClient, module)

    module.exit_json(changed=False, msg=result)


if __name__ == "__main__":
    main()
