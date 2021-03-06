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
module: get_logical_drives_details
description: This module gets the logical drive details for a given server
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
- name: Get logical drives details
  get_logical_drives_details:
    baseuri: "***.***.***.***"
    username: "abcxyz"
    password: "******"
"""

RETURN = r"""
  expected_result:
    description: Returns the logical drive details from the server
    returned: List of logical drives present in the server
    type: list
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
    description: Credentials of server not valid
    returned: InvalidCredentialsError
    corrective_action: Validate the credentials
    type: str
  failure case 4:
    description: Getting SmartStorage details failed
    returned: GET on /redfish/v1/Systems/1/SmartStorage/ Failed, Status <status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 5:
    description: Getting ArrayControllers URI failed
    returned: Array Controllers data not found in redfish/v1/Systems/1/SmartStorage/ response
    corrective_action: Check if server is having ArrayControllers under SmartStorage
    type: str
  failure case 6:
    description: Getting list of ArrayControllers failed
    returned: GET on /redfish/v1/Systems/1/SmartStorage/ArrayControllers/ Failed, Status <status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 7:
    description: Getting ArrayControllers members failed
    returned: GET on /redfish/v1/Systems/1/SmartStorage/ArrayControllers/<controller_ID>/ Failed, Status <status code>,
     Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 8:
    description: Getting logical drives URI failed
    returned: Logical Drives URI not found in /redfish/v1/Systems/1/SmartStorage/ArrayControllers/<controller_ID>/ response
    corrective_action: Check if server is having logical drives URI in the ArrayControllers details
    type: str
  failure case 9:
    description: Getting list of logical drives failed
    returned: GET on /redfish/v1/Systems/1/SmartStorage/ArrayControllers/<controller_ID>/LogicalDrives/ Failed, Status <status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 10:
    description: Getting specific logical drive details failed
    returned: GET on /redfish/v1/Systems/1/SmartStorage/ArrayControllers/<controller_ID>/LogicalDrives/<LogicalDrive_ID>/ Failed, Status <status code>,
     Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 11:
    description: Getting physical drive URI attached to logical drive failed
    returned: Physical Drives information not found in /redfish/v1/Systems/1/SmartStorage/ArrayControllers/<controller_ID>/LogicalDrives/<LogicalDrive_ID>/
     response
    corrective_action: Validate the physical drive details from server
    type: str
  failure case 12:
    description: Getting list of physical drives attached to logical drive failed
    returned: GET on /redfish/v1/Systems/1/SmartStorage/ArrayControllers/<controller_ID>/LogicalDrives/<LogicalDrive_ID>/DataDrives/ Failed,
     Status <status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 13:
    description: Getting specific physical drive details failed
    returned: GET on /redfish/v1/Systems/1/SmartStorage/ArrayControllers/<controller_ID>/DiskDrives/<Disk_ID>/ Failed, Status <status code>,
     Response <API response>
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


def get_logical_drives_details(redfishClient, module):
    # This method makes call to ILO from redfish client to get the number of logical drives under given ILO
    logical_drives_details = []
    body = []

    # Getting smart storage details
    url = "/redfish/v1/Systems/1/SmartStorage/"
    res = redfishClient.get(url)
    if res.status != 200:
        error_msg(module, "GET", url, res.status, res.text)
    json_data = json.loads(res.text)

    # Getting Array Controllers details
    if "ArrayControllers" not in json_data["Links"]:
        module.fail_json(
            msg="Array Controllers data not found in %s response: %s"
            % (url, str(json_data))
        )
    res = redfishClient.get(json_data["Links"]["ArrayControllers"]["@odata.id"])
    if res.status != 200:
        error_msg(
            module,
            "GET",
            json_data["Links"]["ArrayControllers"]["@odata.id"],
            res.status,
            res.text,
        )
    json_data = json.loads(res.text)

    # Getting details for each member in Array Controllers
    for entry in json_data["Members"]:
        log = redfishClient.get(entry["@odata.id"])
        if log.status != 200:
            error_msg(module, "GET", entry["@odata.id"], log.status, log.text)
        log_details = json.loads(log.text)

        # Getting logical drives details
        if "LogicalDrives" not in log_details["Links"]:
            module.fail_json(
                msg="Logical Drives URI not found in %s response: %s"
                % (entry["@odata.id"], str(log_details))
            )
        data = redfishClient.get(log_details["Links"]["LogicalDrives"]["@odata.id"])
        if data.status != 200:
            error_msg(
                module,
                "GET",
                log_details["Links"]["LogicalDrives"]["@odata.id"],
                data.status,
                data.text,
            )
        logicalDrivesData = json.loads(data.text)

        # Getting details for each member in Logical Drives
        for member in logicalDrivesData["Members"]:
            fetched_member_data = redfishClient.get(member["@odata.id"])
            if fetched_member_data.status != 200:
                error_msg(
                    module,
                    "GET",
                    member["@odata.id"],
                    fetched_member_data.status,
                    fetched_member_data.text,
                )
            member_data = remove_odata(json.loads(fetched_member_data.text))

            # Getting data drives details
            if "DataDrives" not in member_data["Links"]:
                module.fail_json(
                    msg="Physical Drives information not found in %s response: %s"
                    % (member["@odata.id"], str(member_data))
                )
            member_data["data_drives"] = []
            data_drive = redfishClient.get(
                member_data["Links"]["DataDrives"]["@odata.id"]
            )
            if data_drive.status != 200:
                error_msg(
                    module,
                    "GET",
                    member_data["Links"]["DataDrives"]["@odata.id"],
                    data_drive.status,
                    data_drive.text,
                )
            data_drive_res = json.loads(data_drive.text)

            # Getting details for each member in Data Drives
            for mem in data_drive_res["Members"]:
                data_drive_fetch = redfishClient.get(mem["@odata.id"])
                if data_drive_fetch.status != 200:
                    error_msg(
                        module,
                        "GET",
                        mem["@odata.id"],
                        data_drive_fetch.status,
                        data_drive_fetch.text,
                    )
                data_drive_member_details = remove_odata(
                    json.loads(data_drive_fetch.text)
                )
                member_data["data_drives"].append(data_drive_member_details)
            logical_drives_details.append(member_data)

    return logical_drives_details


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

    logical_drives_details = get_logical_drives_details(redfishClient, module)

    logout(redfishClient, module)

    module.exit_json(changed=False, logical_drives_details=logical_drives_details)


if __name__ == "__main__":
    main()
