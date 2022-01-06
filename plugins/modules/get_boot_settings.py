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
module: get_boot_settings
description: This module will get network boot settings from a server
requirements:
    - "python >= 3.6"
    - "ansible >= 2.11"
author:
    - "T S Kushal (@TSKushal)"
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
"""

EXAMPLES = r"""
- name: Get network boot settings
  get_boot_settings:
    baseuri: "***.***.***.***"
    username: "abcxyz"
    password: "******"
"""

RETURN = r"""
  expected_result:
    description: Boot settings fetched from the server
    returned: Boot settings present in the server
    type: dict
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
    description: Getting BIOS data failed
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
"""

import json

try:
    from redfish import redfish_client

    HAS_REDFISH = True
except ImportError:
    HAS_REDFISH = False

from ansible.module_utils.basic import AnsibleModule, missing_required_lib


def logout(redfishClient, module):
    redfishClient.logout()


def error_msg(module, method, uri, status, response):
    # Print error message
    module.fail_json(
        msg="%s on %s Failed, Status: %s, Response: %s"
        % (str(method), str(uri), str(status), str(response))
    )


def remove_odata(output):
    # Remove odata variables given in the list
    remove_list = ["@odata.context", "@odata.etag", "@odata.id", "@odata.type"]
    for key in remove_list:
        if key in output:
            output.pop(key)
    return output


def get_network_boot_settings(redfishClient, module):
    """
    Getting network boot order

    Parameters
    ----------
    Null

    Returns
    -------
    res : returns network boot order settings
    """

    uri = "/redfish/v1/Systems/1/bios/boot/settings/"
    response = redfishClient.get(uri)
    if response.status == 404:
        uri = "/redfish/v1/Systems/1/bios/"
        res = redfishClient.get(uri)
        if res.status != 200:
            error_msg(module, "GET", uri, res.status, res.text)
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
        error_msg(module, "GET", uri, response.status, response.text)

    res = remove_odata(json.loads(response.text))
    return res


if __name__ == "__main__":

    module = AnsibleModule(
        argument_spec=dict(
            baseuri=dict(required=True, type="str"),
            username=dict(required=True, type="str"),
            password=dict(required=True, type="str", no_log=True),
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

    network_boot_order = get_network_boot_settings(redfishClient, module)

    logout(redfishClient, module)

    module.exit_json(changed=False, boot_settings=network_boot_order)
