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
module: get_physical_drives_details
description: This module will get physical drive details of a server
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
- name: Get physical drives details
  get_physical_drives_details:
    baseuri: "***.***.***.***"
    username: "abcxyz"
    password: "******"
"""

RETURN = r"""
  expected_result:
    description: Physical drive details fetched from the server
    returned: Physical drives present in the server in each array controller and number of physical drives
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
    description: Getting list of ArrayControllers URI failed
    returned: GET on /redfish/v1/Systems/1/SmartStorage/ArrayControllers/ Failed, Status <Status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 5:
    description: Getting Arraycontrollers member failed
    returned: GET on /redfish/v1/Systems/1/SmartStorage/ArrayControllers/<controller_ID>/ Failed, Status <Status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 6:
    description: Getting physical drive URI failed
    returned: Physical drive URI not found in /redfish/v1/Systems/1/SmartStorage/ArrayControllers/<controller_ID>/ response
    corrective_action: Validate the physical drive details from server
    type: str
  failure case 7:
    description: Getting a list of physical drives failed
    returned: GET on /redfish/v1/Systems/1/SmartStorage/ArrayControllers/<controller_ID>/DiskDrives/ Failed, Status <Status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 8:
    description: Getting specific physical drive details failed
    returned: GET on /redfish/v1/Systems/1/SmartStorage/ArrayControllers/<controller_ID>/DiskDrives/<physical_drive_ID>/ Failed, Status <Status code>, Response <API response>
    corrective_action: Verify the response in the output message
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


def get_physical_drives_details(redfishClient, module):
    # Get ArrayControllers
    physical_drives = {}
    physical_drives_count = 0
    phy_drive_url = "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/"
    res = redfishClient.get(phy_drive_url)
    if res.status != 200:
        error_msg(module, "GET", phy_drive_url, res.status, res.text)
    init_data = json.loads(res.text)
    if init_data["Members@odata.count"] == 0:
        return physical_drives, physical_drives_count

    # Get Members of ArrayControllers
    for mem in init_data["Members"]:
        physical_drive_list = []
        array_url = mem["@odata.id"]
        array_res = redfishClient.get(array_url)
        if array_res.status != 200:
            error_msg(module, "GET", array_url, array_res.status, array_res.text)
        # Get physicaldrives URI
        json_data = json.loads(array_res.text)
        if "Links" in json_data and "PhysicalDrives" in json_data["Links"]:
            log_url = json_data["Links"]["PhysicalDrives"]["@odata.id"]
        elif "links" in json_data and "PhysicalDrives" in json_data["links"]:
            log_url = json_data["links"]["PhysicalDrives"]["href"]
        else:
            module.fail_json(
                "Physical drive URI not found in %s reponse: %s"
                % (array_url, str(json_data))
            )
        # Get list of physicaldrives URI
        resp1 = redfishClient.get(log_url)
        if resp1.status != 200:
            error_msg(module, "GET", log_url, resp1.status, resp1.text)
        json_data1 = json.loads(resp1.text)
        for entry in json_data1["Members"]:
            # Get each physicaldrives details
            log = redfishClient.get(entry["@odata.id"])
            if log.status != 200:
                error_msg(module, "GET", entry["@odata.id"], log.status, log.text)
            log_data = remove_odata(json.loads(log.text))
            physical_drive_list.append(log_data)
        physical_drives.update(
            {"array_controller_" + str(array_url.split("/")[-2]): physical_drive_list}
        )
        physical_drives_count = physical_drives_count + len(physical_drive_list)
    return physical_drives, physical_drives_count


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
    base_url = "{}://{}".format(http_schema, module.params["baseuri"])
    redfishClient = redfish_client(
        base_url=base_url,
        username=module.params["username"],
        password=module.params["password"],
    )
    redfishClient.login()

    physical_drives, physical_drives_count = get_physical_drives_details(
        redfishClient, module
    )

    physical_drives_details = {}
    physical_drives_details["physical_drives"] = physical_drives
    physical_drives_details["physical_drives_count"] = physical_drives_count

    logout(redfishClient, module)

    module.exit_json(changed=False, physical_drives_details=physical_drives_details)
