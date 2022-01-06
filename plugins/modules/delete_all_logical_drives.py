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
module: delete_all_logical_drives
description: This module deletes all logical drives in a given server
requirements:
    - "python >= 3.6"
    - "ansible >= 2.11"
author:
    - "Varini HP (@varini-hp)"
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
- name: Delete all logical drives
  delete_all_logical_drives:
    baseuri: "***.***.***.***"
    username: "abcxyz"
    password: "******"
"""
RETURN = r"""
  expected_result:
    description: Logical drives deleted from the server
    returned: Delete logical drives request sent. System Reset required.
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
    description: Logical drives deletion failed
    returned: Failed to delete logical drive, Status <Status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 4:
    description: Credentials not valid
    returned: InvalidCredentialsError
    corrective_action: Validate the credentials
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


def delete_all_logical_drives(redfishClient, module):
    # This function makes call to Server through redfish client to delete all the logical drive of ILO.

    body = {"LogicalDrives": [], "DataGuard": "Disabled"}
    url = "/redfish/v1/systems/1/smartstorageconfig/settings/"
    res = redfishClient.put(url, body=body)

    if res.status != 200:
        module.fail_json(
            msg="Failed to delete logical drive, Status: %s, Response: %s, Payload: %s, API: %s"
            % (str(res.status), str(res.text), str(body), url)
        )
    return True


def main():
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

    # Create a Redfish client object
    http_schema = module.params["http_schema"]
    base_url = "{0}://{1}".format(http_schema, module.params["baseuri"])
    redfishClient = redfish_client(
        base_url=base_url,
        username=module.params["username"],
        password=module.params["password"],
    )
    redfishClient.login()

    status = delete_all_logical_drives(redfishClient, module)

    logout(redfishClient, module)

    module.exit_json(
        changed=status, msg="Delete logical drives request sent. System Reset required."
    )


if __name__ == "__main__":
    main()
