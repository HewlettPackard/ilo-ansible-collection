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
module: create_logical_drives
description: This module creates logical drives specified by raid_details in a given server
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
  raid_details:
    description:
      - List of RAID details that need to be configured in the given server
    type: list
    default: NONE
    required: true
  LogicalDriveName:
    description:
      - Logical drive name that needs to be configured in the given server
    type: str
    default: NONE
    required: true
  Raid:
    description:
      - Type of RAID
    type: str
    default: NONE
    required: true
  DataDrives:
    description:
      - Specifies the data drive details like media type, interface type, disk count and size
    type: dict
    default: NONE
    required: true
  DataDriveCount:
    description:
      - Number of physical drives that is required to create specified RAID
    type: int
    default: NONE
    required: true
  DataDriveMediaType:
    description:
      - Media type of the disk
    type: str
    default: NONE
    required: true
  DataDriveInterfaceType:
    description:
      - Interface type of the disk
    type: str
    default: NONE
    required: true
  DataDriveMinimumSizeGiB:
    description:
      - Minimum size required in the physical drive
    type: int
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
- name: Create logical drive
  create_logical_drive:
    baseuri: "***.***.***.***"
    username: "abcxyz"
    password: "******"
    raid_details: [{"LogicalDriveName": "LD1",
                     "Raid": "Raid1",
                     "DataDrives": {
                        "DataDriveCount": 2,
                        "DataDriveMediaType": "HDD",
                        "DataDriveInterfaceType": "SAS",
                        "DataDriveMinimumSizeGiB": 0
                        }
                    }]

"""

RETURN = r"""
  expected_result 1:
    description: Logical drives created in the server
    returned: Create logical drives request sent for <list of logical drive names>. System Reset required.
    type: str
  expected_result 2:
    description: Logical drives are already present in the server
    returned: Provided logical drives are already present in the server
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
    returned: GET on /redfish/v1/Systems/1/SmartStorage/ArrayControllers/<controller_ID>/ Failed, Status <status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 8:
    description: Getting logical drives URI failed
    returned: Logical Drives URI not found in /redfish/v1/Systems/1/SmartStorage/ArrayControllers/<controller_ID>/ response
    corrective_action: Check if server is having logical drives URI in the ArrayControllers details
    type: str
  failure case 9:
    description: Getting a list of logical drives failed
    returned: GET on /redfish/v1/Systems/1/SmartStorage/ArrayControllers/<controller_ID>/LogicalDrives/ Failed, Status <status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 10:
    description: Getting specific logical drive details failed
    returned: GET on /redfish/v1/Systems/1/SmartStorage/ArrayControllers/<controller_ID>/LogicalDrives/<LogicalDrive_ID>/ Failed, Status <status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 11:
    description: Getting physical drive URI attached to logical drive failed
    returned: Physical Drives information not found in /redfish/v1/Systems/1/SmartStorage/ArrayControllers/<controller_ID>/LogicalDrives/<LogicalDrive_ID>/ response
    corrective_action: Validate the physical drive details from server
    type: str
  failure case 12:
    description: Getting list of physical drives attached to logical drive failed
    returned: GET on /redfish/v1/Systems/1/SmartStorage/ArrayControllers/<controller_ID>/LogicalDrives/<LogicalDrive_ID>/DataDrives/ Failed, Status <status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 13:
    description: Getting specific physical drive details failed
    returned: GET on /redfish/v1/Systems/1/SmartStorage/ArrayControllers/<controller_ID>/DiskDrives/<Disk_ID>/ Failed, Status <status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 14:
    description: Already logical drive exists with same name but different details
    returned: Already logical drive exists with same name <LogicalDrive name>, but different details
    corrective_action: Modify the logicaldrive name in the input or delete the existing logical drive with same name
    type: str
  failure case 15:
    description: Failed to get SmartStorageConfig details
    returned: GET on /redfish/v1/systems/1/smartstorageconfig/ Failed, Status <status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 16:
    description: Free Physical drives are not available in the server
    returned: Free Physical drives are not available in the server
    corrective_action: Add required physical drive to the server
    type: str
  failure case 17:
    description: Less number of Physical drives available in the server
    returned: Less number of Physical drives available in the server
    corrective_action: Add required physical drive to the server
    type: str
  failure case 18:
    description: Failed to create logical drives
    returned: Failed to create logical drives, Status <Status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 19:
    description: Input parameter is missing
    returned: Input parameters <missing parameter> are missing to create logical drive. Mandatory parameters are ['LogicalDriveName', 'Raid', 'DataDrives'] and in data drive details ['DataDriveCount','DataDriveMediaType','DataDriveInterfaceType','DataDriveMinimumSizeGiB']
    corrective_action: Provide all the input parameters
    type: str
  failure case 20:
    description: Unsupported parameter is provided
    returned: Unsupported input parameters <list of unsupported input parameters>
    corrective_action: Remove wrong parameters from the input
    type: str
  failure case 21:
    description: Unsupported parameter is provided in data drive details
    returned: Unsupported input parameters in data drive details <list of unsupported input parameters>
    corrective_action: Remove wrong parameters from the data drive details
    type: str
  failure case 22:
    description: Input parameters value is empty
    returned: Input parameters <list of input parameters> should not be empty
    corrective_action: Provided value for all input parameters
    type: str
  failure case 23:
    description: Getting unconfigured drive URI failed
    returned: Unconfigured drive URI not found in /redfish/v1/Systems/1/SmartStorage/ArrayControllers/<controller_ID>/ response
    corrective_action: Validate the unconfigured physical drives details from server
    type: str
  failure case 24:
    description: Getting a list of unconfigured physical drives failed
    returned: GET on /redfish/v1/Systems/1/SmartStorage/ArrayControllers/<controller_ID>/UnconfiguredDrives/ Failed, Status <Status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 25:
    description: Getting specific unconfigured physical drive details failed
    returned: GET on /redfish/v1/Systems/1/SmartStorage/ArrayControllers/<controller_ID>/DiskDrives/<physical_drive_ID>/ Failed, Status <Status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 26:
    description: Free physical drive not found with required specification
    returned: Free physical drive not found with media type <media type>, interface type <interface type>, and capacity <minimum size required in physical drive>
    corrective_action: Verify the physical drives available in the server
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


def get_logical_drives_details(redfishClient, module):
    # This method makes call to ILO from redfish client to get the number of logical drives under given ILO
    logical_drives_details = []
    logical_drives_count = 0
    body = []
    unused_physical_drives = []

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
        if "UnconfiguredDrives" not in log_details["Links"]:
            module.fail_json(
                msg="Unconfigured Drives URI not found in %s response: %s"
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
            member_data = json.loads(fetched_member_data.text)

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
                data_drive_member_details = json.loads(data_drive_fetch.text)
                member_data["data_drives"].append(data_drive_member_details)
            logical_drives_details.append(member_data)
        unused_physical_drives = unused_physical_drives + get_unused_drives(
            redfishClient,
            log_details["Links"]["UnconfiguredDrives"]["@odata.id"],
            module,
        )
    return logical_drives_details, unused_physical_drives


def get_unused_drives(redfishClient, phy_url, module):
    physical_drive_list = []
    resp1 = redfishClient.get(phy_url)
    if resp1.status != 200:
        error_msg(module, "GET", phy_url, resp1.status, resp1.text)
    json_data1 = json.loads(resp1.text)
    for entry in json_data1["Members"]:
        # Get each physicaldrives details
        log = redfishClient.get(entry["@odata.id"])
        if log.status != 200:
            error_msg(module, "GET", entry["@odata.id"], log.status, log.text)
        physical_drive_list.append(json.loads(log.text))
    return physical_drive_list


def print_input_validation_error(
    raid, input_list, drive_input, missing_param, not_defined, module
):
    if missing_param:
        msg = (
            "Input parameters %s are missing to create logical drive. "
            + "Mandatory parameters are %s and in data drive details: %s"
        )
        module.fail_json(
            msg=msg % (str(missing_param), str(input_list), str(drive_input))
        )

    if set(raid.keys()) - set(input_list):
        module.fail_json(
            msg="Unsupported input parameters: %s"
            % str(list(set(raid.keys()) - set(input_list)))
        )

    if set(raid["DataDrives"].keys()) - set(drive_input):
        msg = "Unsupported input parameters in data drive details: %s"
        module.fail_json(
            msg=msg % str(list(set(raid["DataDrives"].keys()) - set(drive_input)))
        )

    if not_defined:
        module.fail_json(
            msg="Input parameters %s should not be empty" % (str(not_defined))
        )


def verify_input_paramters(raid_data, module):
    # Verifying input parameters
    input_list = ["LogicalDriveName", "Raid", "DataDrives"]
    drive_input = [
        "DataDriveCount",
        "DataDriveMediaType",
        "DataDriveInterfaceType",
        "DataDriveMinimumSizeGiB",
    ]
    for raid in raid_data:
        missing_param = []
        not_defined = []
        for input in input_list:
            if input not in raid.keys():
                missing_param.append(input)
            elif not raid[input]:
                not_defined.append(input)
        if "DataDrives" not in raid.keys():
            missing_param = missing_param + drive_input
        else:
            for drive in drive_input:
                if drive not in raid["DataDrives"].keys():
                    missing_param.append(drive)
                elif (
                    drive != "DataDriveMinimumSizeGiB" and not raid["DataDrives"][drive]
                ):
                    not_defined.append(drive)
                elif (
                    drive == "DataDriveMinimumSizeGiB"
                    and not raid["DataDrives"]["DataDriveMinimumSizeGiB"]
                    and raid["DataDrives"]["DataDriveMinimumSizeGiB"] != 0
                ):
                    not_defined.append(drive)
        print_input_validation_error(
            raid, input_list, drive_input, missing_param, not_defined, module
        )


def check_physical_drives(raid, unused_physical_drives):
    unused_drives = unused_physical_drives[:]
    for phy in unused_physical_drives:
        if (
            raid["DataDrives"]["DataDriveMediaType"] == phy["MediaType"]
            and raid["DataDrives"]["DataDriveInterfaceType"] == phy["InterfaceType"]
            and int(raid["DataDrives"]["DataDriveMinimumSizeGiB"])
            <= int(phy["CapacityGB"]) * 0.931323
        ):
            unused_drives.remove(phy)
            return unused_drives
    return "failed"


def verify_physical_drives(raid_data, unused_physical_drives, module):
    raid_data = sorted(
        raid_data, key=lambda i: i["DataDrives"]["DataDriveMinimumSizeGiB"]
    )
    unused_physical_drives = sorted(
        unused_physical_drives, key=lambda i: i["CapacityGB"]
    )
    for raid in raid_data:
        for i in range(0, int(raid["DataDrives"]["DataDriveCount"])):
            result = check_physical_drives(raid, unused_physical_drives)
            if str(result) == "failed":
                msg = (
                    "Free physical drive not found with media type: %s,"
                    + " interface type: %s, and capacity: %s"
                )
                module.fail_json(
                    msg=msg
                    % (
                        raid["DataDrives"]["DataDriveMediaType"],
                        raid["DataDrives"]["DataDriveInterfaceType"],
                        str(raid["DataDrives"]["DataDriveMinimumSizeGiB"]),
                    )
                )
            unused_physical_drives = result


def verify_logical_drives(module, raid, logical_drives_details):
    # Verifying whether logical drive already exists
    for drive in logical_drives_details:
        if drive["LogicalDriveName"] == raid["LogicalDriveName"]:
            if (
                ("Raid" + drive["Raid"]) != raid["Raid"]
                or len(drive["data_drives"]) != raid["DataDrives"]["DataDriveCount"]
                or drive["MediaType"] != raid["DataDrives"]["DataDriveMediaType"]
                or drive["InterfaceType"]
                != raid["DataDrives"]["DataDriveInterfaceType"]
            ):
                module.fail_json(
                    msg="Already logical drive exists with same name: '%s', but different details"
                    % str(drive["LogicalDriveName"])
                )
            for data_drive in drive["data_drives"]:
                if (
                    int(data_drive["CapacityGB"]) * 0.931323
                    < raid["DataDrives"]["DataDriveMinimumSizeGiB"]
                ):
                    module.fail_json(
                        msg="Already logical drive exists with same name: '%s', but different details"
                        % str(drive["LogicalDriveName"])
                    )
            return True
    return False


def check_physical_drive_count(module, raid_data, unused_physical_drives):
    # Check physical drives are available to create logical drives
    # Check required physical drives
    needed_phy = 0
    for ld in raid_data:
        needed_phy = needed_phy + int(ld["DataDrives"]["DataDriveCount"])

    # Check available drives
    if not unused_physical_drives:
        module.fail_json(msg="Free Physical drives are not available in the server")
    if len(unused_physical_drives) < needed_phy:
        module.fail_json(msg="Less number of Physical drives available in the server")


def create_logical_drive(redfishClient, module):
    # This function invokes the creation of logical drive.
    # read raid_details from input
    raid_data = module.params["raid_details"]
    # verify input parameters
    verify_input_paramters(raid_data, module)
    # Get logical drives from server
    logical_drives_details, unused_physical_drives = get_logical_drives_details(
        redfishClient, module
    )

    if logical_drives_details:
        raid_details = raid_data[:]
        for raid in raid_details:
            if verify_logical_drives(module, raid, logical_drives_details):
                raid_data.remove(raid)
    if not raid_data:
        module.exit_json(
            changed=False,
            msg="Provided logical drives are already present in the server",
        )

    check_physical_drive_count(module, raid_data, unused_physical_drives)
    verify_physical_drives(raid_data, unused_physical_drives, module)

    res = redfishClient.get("/redfish/v1/systems/1/smartstorageconfig/")
    storage_data = json.loads(res.text)
    if res.status != 200:
        error_msg(
            module,
            "GET",
            "/redfish/v1/systems/1/smartstorageconfig/",
            res.status,
            res.text,
        )

    ld_names = [i["LogicalDriveName"] for i in raid_data]
    LogicalDrives = storage_data["LogicalDrives"]
    body = {}
    body["LogicalDrives"] = LogicalDrives + raid_data
    body["DataGuard"] = "Permissive"
    url = "/redfish/v1/systems/1/smartstorageconfig/settings/"
    res = redfishClient.put(url, body=body)

    # Checking the status of response of redfish client for the logical drive creation
    if res.status != 200:
        module.fail_json(
            msg="Failed to create logical drives, Status: %s, Response: %s, Payload: %s, API: %s"
            % (str(res.status), str(res.text), str(body), url)
        )
    return ld_names


def main():
    module = AnsibleModule(
        argument_spec=dict(
            baseuri=dict(required=True, type="str"),
            username=dict(required=True, type="str"),
            password=dict(required=True, type="str", no_log=True),
            raid_details=dict(required=True, type="list"),
            http_schema=dict(required=False, default="https", type="str"),
        )
    )

    if not HAS_REDFISH:
        module.fail_json(msg=missing_required_lib("redfish"))

    # Create a Redfish client object
    http_schema = module.params["http_schema"]
    base_url = "{}://{}".format(http_schema, module.params["baseuri"])
    redfishClient = redfish_client(
        base_url=base_url,
        username=module.params["username"],
        password=module.params["password"],
    )
    redfishClient.login()

    ld_names = create_logical_drive(redfishClient, module)

    logout(redfishClient, module)

    module.exit_json(
        changed=True,
        msg="Create logical drives request sent for %s. System Reset required."
        % str(ld_names),
    )


if __name__ == "__main__":
    main()
