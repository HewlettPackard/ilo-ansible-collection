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
module: check_reboot_status
description: This module checks reboot status of a server
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
  http_schema:
    description:
      - http or https Protocol
    type: str
    default: https
    required: false
"""

EXAMPLES = r"""
- name: Check server reboot status
  check_reboot_status:
    baseuri: "***.***.***.***"
    username: "abcxyz"
    password: "******"
"""
RETURN = r"""
  expected_result 1:
    description: Server reboot is completed
    returned: Server reboot is completed
    type: str
  expected_result 2:
    description: Server is not rebooting and powered ON
    returned: Server is not rebooting
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
    description: Getting server data failed
    returned: GET on /redfish/v1/systems/1/ Failed, Status <Status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 5:
    description: Server is powered OFF
    returned: Server is powered OFF
    corrective_action: Server has to be switched on to proceed
    type: str
  failure case 6:
    description: Server Reboot has failed
    returned: Server Reboot has failed, server state <server state>
    corrective_action: Check the server status
    type: str
"""

import time
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


def error_msg(module, method, uri, status, response):
    # Print error message
    module.fail_json(
        msg="%s on %s Failed, Status: %s, Response: %s"
        % (str(method), str(uri), str(status), str(response))
    )


def get_server_poststate(redfishClient, module):
    # Get server details
    uri = base_uri + system_uri
    server_data = redfishClient.get(uri)
    if server_data.status != 200:
        error_msg(module, "GET", uri, server_data.status, server_data.text)
    server_details = json.loads(server_data.text)
    if "Hpe" in server_details["Oem"]:
        return server_details["Oem"]["Hpe"]["PostState"]
    else:
        return server_details["Oem"]["Hp"]["PostState"]


def check_reboot_status(
    redfishClient, module, polling_interval=60, max_polling_time=600
):
    time.sleep(10)

    # Check server poststate
    state = get_server_poststate(redfishClient, module)
    count = int(max_polling_time / polling_interval)
    times = 0

    # When server is powered OFF
    if state in ["PowerOff", "Off"]:
        logout(redfishClient, module)
        module.fail_json(msg="Server is powered OFF")

    # When server is not rebooting
    if state in ["InPostDiscoveryComplete", "FinishedPost"]:
        logout(redfishClient, module)
        module.exit_json(changed=False, msg="Server is not rebooting")

    while state not in ["InPostDiscoveryComplete", "FinishedPost"] and count > times:
        state = get_server_poststate(redfishClient, module)
        if state == "InPostDiscoveryComplete" or state == "FinishedPost":
            logout(redfishClient, module)
            module.exit_json(changed=True, msg="Server reboot is completed")
        time.sleep(polling_interval)
        times = times + 1
    module.fail_json(
        msg="Server Reboot has failed, server state: {state} ".format(state=state)
    )


def main():
    module = AnsibleModule(
        argument_spec=dict(
            baseuri=dict(required=True, type="str"),
            username=dict(required=False, default=None, type="str"),
            password=dict(required=False, default=None, type="str", no_log=True),
            http_schema=dict(required=False, default="https", type="str"),
        )
    )

    if not HAS_REDFISH:
        module.fail_json(msg=missing_required_lib("redfish"))

    baseuri = module.params["baseuri"]
    username = module.params["username"]
    password = module.params["password"]
    http_schema = module.params["http_schema"]

    base_url = "{}://{}".format(http_schema, baseuri)
    redfishClient = redfish_client(
        base_url=base_url, username=username, password=password
    )
    redfishClient.login()
    check_reboot_status(redfishClient, module)


if __name__ == "__main__":
    main()
