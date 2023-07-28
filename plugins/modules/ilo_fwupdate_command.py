#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2021-2022 Hewlett Packard Enterprise, Inc. All rights reserved.
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ilo_fwupdate_command
short_description: Sets or updates configuration attributes on HPE iLO with Redfish OEM extensions
version_added: 4.2.0
description:
  - Builds Redfish URIs locally and sends them to iLO to
    perform an action.
  - For use with HPE iLO operations that require Redfish OEM extensions.
options:
  category:
    required: true
    type: str
    description:
      - Command category to execute on iLO.
    choices: ['UpdateService']
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
      - Username for authenticating to iLO.
    type: str
  password:
    description:
      - Password for authenticating to iLO.
    type: str
  timeout:
    description:
      - Timeout in seconds for HTTP requests to iLO.
    default: 10
    type: int
  attribute_name:
    required: true
    description:
      - Name of the attribute to be configured.
    type: str
  attribute_value:
    required: false
    description:
      - Value of the attribute to be configured.
    type: str
  fwpkg_file:
    required: false
    description:
      - Absolute path of the firmware package file that the user wishes to attach.
  force:
    required: false
    description:
      - Add this flag to force upload components with the same name already on the repository.
  tover:
    required: false
    description:
      - Use this flag if the server you are currently logged into has a TPM chip installed.
  update_srs:
    required: false
    description:
      - The component uploaded will become a part of the system recovery set (srs).
  componentsig:
    required: false
    description:
      - Component signature file path needed by iLO to authenticate the component file.
        If not provided, the command will try to find the signature file from component file path.
  overwrite:
    required: false
    description:
      - Permission to overwrite a file present of the server with same name.
  remote:
    required: false
    description:
      - Remote file path where the file is present.
  install_filename:
    required: false
    description:
      - Name of the file package that needs to be installed.
author:
    - "Bhavya B (@bhavya06)"
'''

EXAMPLES = '''
  - name: Flash Firmware package for Bios
    ilo_fwupdate_command:
        category: UpdateService
        command: Flashfwpkg
        baseuri: "15.x.x.x"
        username: "Admin"
        password: "testpass123"
        fwpkg_file: Bios_fwpkgfile.fwpkg

  - name: Flash Firmware package for iLO
    ilo_fwupdate_command:
        category: UpdateService
        command: Flashfwpkg
        baseuri: "15.x.x.x"
        username: "Admin"
        password: "testpass123"
        fwpkg_file: ilo_fwpkgfile.fwpkg
'''

RETURN = '''
msg:
    description: Message with action result or error description
    returned: always
    type: str
    sample: "Action was successful"
'''

CATEGORY_COMMANDS_ALL = {
    "UpdateService": ["Flashfwpkg", "UploadComponent"],
    "RLCP": ["PackageInstall", "SmtCmpInstall"]
}

from ansible_collections.hpe.ilo.plugins.module_utils.ilo_oem_utils import iLOOemUtils
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native


def main():
    result = {}
    module = AnsibleModule(
        argument_spec=dict(
            category=dict(required=True, choices=list(
                CATEGORY_COMMANDS_ALL.keys())),
            command=dict(required=True, type='list', elements='str'),
            baseuri=dict(required=True),
            username=dict(required=True),
            password=dict(required=True, no_log=True),
            fwpkg_file=dict(type='str'),
            force=dict(type='bool', default=True),
            tover=dict(type='bool', default=False),
            update_srs=dict(type='bool', default=False),
            componentsig=dict(type='str', default=''),
            overwrite=dict(type='bool', default=False),
            update_target=dict(type='bool', default=False),
            update_repository=dict(type='bool', default=True),
            remote=dict(type='str'),
            install_filename=dict(type='str'),
            timeout=dict(type='int', default=10)
        ),
        required_together=[
            ('username', 'password'),
        ],
        required_one_of=[
            ('username', 'auth_token'),
        ],
        mutually_exclusive=[
            ('username', 'auth_token'),
        ],
        supports_check_mode=False
    )

    category = module.params['category']
    command_list = module.params['command']

    creds = {"user": module.params['username'],
             "pswd": module.params['password']}

    options = {}

    options["fwpkgfile"] = module.params['fwpkg_file']
    options["forceupload"] = module.params['force']
    options["tover"] = module.params['tover']
    options["update_srs"] = module.params['update_srs']
    options["componentsig"] = module.params['componentsig']
    options["overwrite"] = module.params['overwrite']
    options["update_target"] = module.params['update_target']
    options["update_repository"] = module.params['update_repository']
    if "UploadComponent" in command_list:
        options["component"] = module.params['fwpkg_file']

    timeout = module.params['timeout']

    rpm_info = {}
    rpm_info["OSIP"] = module.params['baseuri']
    rpm_info["os_username"] = module.params['username']
    rpm_info["os_password"] = module.params['password']
    rpm_info["remote"] = module.params['remote']
    rpm_info["file_name"] = module.params['install_filename']

    root_uri = "https://" + module.params['baseuri']
    rf_utils = iLOOemUtils(creds, root_uri, timeout, module)

    offending = [
        cmd for cmd in command_list if cmd not in CATEGORY_COMMANDS_ALL[category]]

    if offending:
        module.fail_json(msg=to_native("Invalid Command(s): '%s'. Allowed Commands = %s" % (
            offending, CATEGORY_COMMANDS_ALL[category])))

    if category == "UpdateService":
        resource = rf_utils._find_updateservice_resource()
        if module.params['fwpkg_file'] == '':
            module.fail_json(msg="Fwpkg file is required.")
        if not resource['ret']:
            module.fail_json(msg=to_native(resource['msg']))

        for command in command_list:
            if command == "Flashfwpkg":
                result = rf_utils.flash_firmware(options)

            if command == "UploadComponent":
                result = rf_utils.uploadcomp(options)
                result['changed'] = True

        if result['ret'] is True:
            if result.get('warning'):
                module.warn(to_native(result['warning']))

            module.exit_json(changed=result['changed'], msg=to_native(result))
        else:
            module.fail_json(msg=to_native(result['msg']))

    elif category == "RLCP":
        for command in command_list:
            if command == "PackageInstall":
                result = rf_utils.install_rpm(rpm_info)

            if command == "SmtCmpInstall":
                result = rf_utils.install_smartcomp(rpm_info)

        if result['ret'] is True:
            if result.get('warning'):
                module.warn(to_native(result['warning']))

            module.exit_json(changed=result['changed'], msg=to_native(result))
        else:
            module.fail_json(msg=to_native(result['msg']))


if __name__ == '__main__':
    main()
