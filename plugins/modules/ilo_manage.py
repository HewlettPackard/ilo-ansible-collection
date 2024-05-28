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

__metaclass__ = type

DOCUMENTATION = """
---
module: ilo_manage
short_description: Performs Management related operations on iLO using Redfish APIs
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
  required_permissions:
    description:
      - permissions to be checked against provided user
    type: list
    elements: str
    default: ["HostBIOSConfigPriv", "HostNICConfigPriv", "HostStorageConfigPriv"]
author:
  - Gayathiri Devi Ramasamy (@Gayathirideviramasamy)
  - T S Kushal (@TSKushal)
  - Varni H P (@varini-hp)
  - Prativa Nayak (@prativa-n)
  - Nagendra M (@nagendram399)
"""

EXAMPLES = """
  - name: Wait for iLO Reboot Completion
    ilo_manage:
      category: Systems
      command: WaitforiLORebootCompletion
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"

  - name: Check User Privileges
    ilo_manage:
      category: Systems
      command: CheckUserPrivileges
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"

  - name: Perform factory reset on the iLO
    ilo_manage:
      category: Manager
      command: iLOFactoryReset
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"

  - name: Get the iLO backup file(s) details
    ilo_manage:
      category: Manager
      command: GetiLOBackupFiles
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"

  - name: Delete iLO backup file(s) if already present
    ilo_manage:
      category: Manager
      command: DeleteiLOBackupFiles
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"

  - name: Perform backup operation on the iLO
    ilo_manage:
      category: Manager
      command: iLOBackup
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"

  - name: Perform restore operation on the iLO
    ilo_manage:
      category: Manager
      command: iLORestore
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"

  - name: Get HostName from the iLO
    ilo_manage:
      category: Manager
      command: GetHostName
      baseuri: "{{ baseuri }}"
      username: "{{ username }}"
      password: "{{ password }}"
"""

RETURN = """
ilo_manage:
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

CATEGORY_COMMANDS_ALL = {"Systems": ["WaitforiLORebootCompletion", "CheckUserPrivileges"],
                         "Manager": ["iLOFactoryReset", "DeleteiLOBackupFiles", "iLOBackup", "iLORestore", "GetiLOBackupFiles", "GetHostName"]}

CATEGORY_COMMANDS_DEFAULT = {"Systems": "WaitforiLORebootCompletion",
                             "Manager": "GetiLOBackupFiles"}

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
            required_permissions=dict(required=False, type="list", elements='str', deafult=["HostBIOSConfigPriv", "HostNICConfigPriv", "HostStorageConfigPriv"])
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

    # Set required permissions to be checked on the server
    required_permissions = module.params["required_permissions"]

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

            for command in command_list:
                if command == "WaitforiLORebootCompletion":
                    result[command] = rf_utils.wait_for_ilo_reboot_completion()
                elif command == "CheckUserPrivileges":
                    result[command] = rf_utils.check_user_privileges(module.params["baseuri"], required_permissions)

        elif category == "Manager":
            result = rf_utils._find_managers_resource()
            if result['ret'] is False:
                module.fail_json(msg=to_native(result['msg']))

            for command in command_list:
                if command == "iLOFactoryReset":
                    result[command] = rf_utils.factory_reset()
                elif command == "GetiLOBackupFiles":
                    result[command] = rf_utils.get_ilo_backupfiles()
                elif command == "DeleteiLOBackupFiles":
                    result[command] = rf_utils.delete_ilo_backupfiles()
                elif command == "iLOBackup":
                    result[command] = rf_utils.ilo_backup()
                elif command == "iLORestore":
                    result[command] = rf_utils.ilo_restore()
                elif command == "GetHostName":
                    result[command] = rf_utils.get_hostname()

    if not result[command]['ret']:
        module.fail_json(msg=to_native(result))

    module.exit_json(ilo_manage=result)


if __name__ == "__main__":
    main()
