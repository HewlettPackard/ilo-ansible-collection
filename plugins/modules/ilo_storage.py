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
module: ilo_storage
short_description: Performs Storage related operations on iLO using Redfish APIs
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
  raid_details:
    description:
      - List of RAID details that need to be configured in the given server.
    type: list
    elements: dict
    suboptions:
      LogicalDriveName:
        required: true
        description:
          - Logical drive name that needs to be configured in the given server
        type: str
      Raid:
        required: true
        description:
          - Type of RAID
        type: str
      DataDrives:
        required: true
        description:
          - Specifies the data drive details like media type, interface type, disk count and size
        type: dict
      DataDriveCount:
        required: true
        description:
          - Number of physical drives that is required to create specified RAID
        type: int
      DataDriveMediaType:
        required: true
        description:
          - Media type of the disk
        type: str
      DataDriveInterfaceType:
        required: true
        description:
          - Interface type of the disk
        type: str
      DataDriveMinimumSizeGiB:
        required: true
        description:
          - Minimum size required in the physical drive
        type: int
  logical_drives_names:
    description:
      - logical drives names which are to be deleted
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
  - name: Get physical drive details
    ilo_storage:
      category: Systems
      command: GetPhysicalDrives
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"

  - name: Get logical drive details
    ilo_storage:
      category: Systems
      command: GetLogicalDrives
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"

  - name: Get logical drive details with array controllers
    ilo_storage:
      category: Systems
      command: GetLogicalDrivesWithArrayControllers
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"

  - name: Get specified logical drives details
    ilo_storage:
      category: Systems
      command: GetSpecifiedLogicalDrives
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"
      logical_drives_names: ["LD1", "LD2"]

  - name: Create logical drive
    ilo_storage:
      category: Systems
      command: CreateLogicalDrives
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"
      raid_details:
        - LogicalDriveName: LD1
          Raid: Raid1
          DataDrives:
              DataDriveCount: 2
              DataDriveMediaType: HDD
              DataDriveInterfaceType: SAS
              DataDriveMinimumSizeGiB: 0

  - name: Create logical drives with particular physical drives
    ilo_storage:
      category: Systems
      command: CreateLogicalDrivesWithParticularPhysicalDrives
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"
      raid_details:
        - LogicalDriveName: LD1
          Raid: Raid1
          CapacityGB: 1200,
          DataDrives: ["1I:1:1", "1I:1:2"]

  - name: Delete all logical drives
    ilo_storage:
      category: Systems
      command: DeleteAllLogicalDrives
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"

  - name: Delete specified logical drives
    ilo_storage:
      category: Systems
      command: DeleteSpecifiedLogicalDrives
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"
      logical_drives_names: ["LD1", "LD2"]

  - name: Verify logical drives
    ilo_storage:
      category: Systems
      command: VerifyLogicalDrives
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"
      raid_details:
        - LogicalDriveName: LD1
          Raid: Raid1
          DataDrives:
              DataDriveCount: 2
              DataDriveMediaType: HDD
              DataDriveInterfaceType: SAS
              DataDriveMinimumSizeGiB: 0

  - name: Verify specified logical drives
    ilo_storage:
      category: Systems
      command: VerifySpecifiedLogicalDrives
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"
      raid_details:
        - LogicalDriveName: LD1
          Raid: Raid1
          DataDrives:
              DataDriveCount: 2
              DataDriveMediaType: HDD
              DataDriveInterfaceType: SAS
              DataDriveMinimumSizeGiB: 0

  - name: Get USB information
    ilo_storage:
      category: Systems
      command: GetUSBInfo
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"

  - name: Erase Physical Drives
    ilo_storage:
      category: Systems
      command: ErasePhysicalDrives
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"

  - name: Get Drive Operating Mode
    ilo_storage:
      category: Systems
      command: GetDriveOperatingMode
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"
"""

RETURN = """
ilo_storage:
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
    "Systems": [
        "GetPhysicalDrives",
        "GetLogicalDrives",
        "GetSpecifiedLogicalDrives",
        "CreateLogicalDrives",
        "CreateLogicalDrivesWithParticularPhysicalDrives",
        "DeleteAllLogicalDrives",
        "DeleteSpecifiedLogicalDrives",
        "VerifyLogicalDrives",
        "VerifySpecifiedLogicalDrives",
        "GetUSBInfo",
        "ErasePhysicalDrives",
        "GetDriveOperatingMode"
    ]}

CATEGORY_COMMANDS_DEFAULT = {
    "Systems": "GetPhysicalDrives"
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
            raid_details=dict(type="list", elements='dict'),
            logical_drives_names=dict(type='list', elements='str')
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
        if category == "Systems":
            result = rf_utils._find_systems_resource()
            if result['ret'] is False:
                module.fail_json(msg=to_native(result['msg']))

            resource = rf_utils._find_managers_resource()
            if resource['ret'] is False:
                module.fail_json(msg=resource['msg'])

            for command in command_list:
                if command == "GetPhysicalDrives":
                    result[command] = rf_utils.get_physical_drives()
                elif command == "GetLogicalDrives":
                    result[command] = rf_utils.get_logical_drives()
                elif command == "GetSpecifiedLogicalDrives":
                    result[command] = rf_utils.get_specified_logical_drives(module.params["logical_drives_names"])
                elif command == "CreateLogicalDrives":
                    result[command] = rf_utils.create_logical_drives(module.params["raid_details"])
                elif command == "CreateLogicalDrivesWithParticularPhysicalDrives":
                    result[command] = rf_utils.create_logical_drives_with_particular_physical_drives(module.params["raid_details"])
                elif command == "DeleteAllLogicalDrives":
                    result[command] = rf_utils.delete_all_logical_drives()
                elif command == "DeleteSpecifiedLogicalDrives":
                    result[command] = rf_utils.delete_specified_logical_drives(module.params["logical_drives_names"])
                elif command == "VerifyLogicalDrives":
                    result[command] = rf_utils.verify_logical_drives(module.params["raid_details"], True)
                elif command == "VerifySpecifiedLogicalDrives":
                    result[command] = rf_utils.verify_logical_drives(module.params["raid_details"], False)
                elif command == "GetUSBInfo":
                    result[command] = rf_utils.get_usb_info()
                elif command == "ErasePhysicalDrives":
                    result[command] = rf_utils.erase_physical_drives()
                elif command == "GetDriveOperatingMode":
                    result[command] = rf_utils.get_drive_operating_mode(module.params['baseuri'])

    if not result[command]['ret']:
        module.fail_json(msg=to_native(result))

    module.exit_json(ilo_storage=result)


if __name__ == "__main__":
    main()
