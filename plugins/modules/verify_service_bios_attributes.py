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
module: verify_service_bios_attributes
description: This module verifies service BIOS settings with provided input data
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
  service_attributes:
    description:
      - service BIOS attributes that needs to be verified in the given server
    type: dict
    default: NONE
    required: true
  http_schema:
    description:
      - http or https Protocol
    default: https
    required: false
    type: str
"""

EXAMPLES = r"""
- name: Verify service BIOS options
  verify_service_bios_attributes:
    baseuri: "***.***.***.***"
    username: "abcxyz"
    password: "*****"
    service_attributes:
      ProcMonitorMwait: "Disabled"
      MemPreFailureNotification": "Enabled"
"""

RETURN = r"""
  expected_result:
    description: Service BIOS settings in the server is matching with service BIOS parameters passed
    returned: Service BIOS verification completed
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
    description: Getting bios URI failed
    returned: Getting BIOS URI Failed, Key Bios not found in /redfish/v1/systems/1/ response
    corrective_action: BIOS API not found in the server details returned. Verify BIOS details in the server
    type: str
  failure case 6:
    description: Getting Service settings failed
    returned: GET on /redfish/v1/systems/1/bios/service/settings/ Failed, Status <Status code>, Response <API response> (or) GET on /redfish/v1/systems/1/bios/oem/hpe/service/settings/ Failed, Status <Status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 7:
    description: Wrong parameters are provided
    returned: Wrong parameters are provided <wrong parameters>
    corrective_action: Verify the service bios parameters passed
    type: str
  failure case 8:
    description: Service BIOS parameters are not matching
    returned: Service BIOS parameters are not matching <parameters which are not matching>
    corrective_action: Expected output if service BIOS parameters are not macthing
    type: str

"""

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


def get_service_bios_attributes(redfishClient, module):
    # Get system details
    uri = base_uri + system_uri
    server_data = redfishClient.get(uri)
    if server_data.status != 200:
        error_msg(module, "GET", uri, server_data.status, server_data.text)
    server_details = json.loads(server_data.text)
    if "Bios" not in server_details:
        module.fail_json(
            msg="Getting BIOS URI Failed, Key 'Bios' not found in %s response: %s"
            % (uri, str(server_details))
        )
    bios_uri = server_details["Bios"]["@odata.id"]

    # Getting service settings
    service_uri = bios_uri + "service/settings/"
    response = redfishClient.get(service_uri)
    # Check if service API doesn't support
    if response.status == 404:
        # call different API if response is 404
        service_uri = bios_uri + "oem/hpe/service/settings/"
        response = redfishClient.get(service_uri)
    # Fail if GET response is not 200
    if response.status != 200:
        error_msg(module, "GET", service_uri, response.status, response.text)
    details = json.loads(response.text)
    return details["Attributes"]


def verify_servicebios(redfishClient, module):
    service_attributes = module.params["service_attributes"]
    server_service_bios = get_service_bios_attributes(redfishClient, module)

    service_dict = {}
    wrong_param = {}
    # Verify service attributes with service BIOS settings available in the server
    for key, value in service_attributes.items():
        if key in server_service_bios:
            if str(server_service_bios[key]).lower() != str(value).lower():
                service_dict.update({key: value})
        else:
            wrong_param.update({key: value})
    if wrong_param:
        module.fail_json(msg="Wrong parameters are provided: %s" % str(wrong_param))
    if service_dict:
        module.fail_json(
            msg="Service BIOS parameters are not matching: %s" % str(service_dict)
        )


def main():
    module = AnsibleModule(
        argument_spec=dict(
            baseuri=dict(required=True, type="str"),
            username=dict(required=True, type="str"),
            password=dict(required=True, type="str", no_log=True),
            service_attributes=dict(required=True, type="dict"),
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

    verify_servicebios(redfishClient, module)
    logout(redfishClient, module)
    module.exit_json(changed=False, msg="Service BIOS verification completed")


if __name__ == "__main__":
    main()
