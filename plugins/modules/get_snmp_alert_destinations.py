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
module: get_snmp_alert_destinations
description: This module will get SNMP alert destinations from a server
requirements:
    - "python >= 3.6"
    - "ansible >= 2.11"
author:
    - "Gayathiri Devi Ramasamy (@Gayathirideviramasamy)"
options:
  baseuri:
    description:
      - iLO IP address of the server
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
- name: Get SNMP alert destinations
  get_snmp_alert_destinations:
    baseuri: "***.***.***.***"
    username: "abcxyz"
    password: "******"
"""

RETURN = r"""
  expected_result:
    description: SNMP alert destinations data fetched from the server
    returned: List of SNMP alert destinations present in the server
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
    description: Credentials not valid
    returned: InvalidCredentialsError
    corrective_action: Validate the credentials
    type: str
  failure case 4:
    description: Getting managers data failed
    returned: GET on /redfish/v1/Managers/1/ Failed, Status <Status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 5:
    description: Getting list of SNMP alert destinations failed
    returned: GET on /redfish/v1/Managers/1/SnmpService/SNMPAlertDestinations/ Failed, Status <Status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 6:
    description: Getting particular SNMP alert destination failed
    returned: GET on /redfish/v1/Managers/1/SnmpService/SNMPAlertDestinations/<alert_destination ID>/ Failed, Status <Status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 7:
    description: Getting SNMPv3 users details attached to alert destination failed
    returned: GET on /redfish/v1/Managers/1/SnmpService/SNMPUsers/<SNMPv3 user ID>/ Failed, Status <Status code>, Response <API response>
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

base_uri = "/redfish/v1/"
manager_uri = "Managers/1/"


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


def get_user_details(redfishClient, output, module):
    # Fetch SNMPv3 user details attached to alert destination
    user_uri = output["SNMPv3User"]["@odata.id"]
    user_res = redfishClient.get(user_uri)
    if user_res.status != 200:
        error_msg(module, "GET", user_uri, user_res.status, user_res.text)
    output["SNMPv3User"] = remove_odata(json.loads(user_res.text))
    return output


def get_alert_destinations(redfishClient, module):
    # Get on Managers API
    alert_destinations = []
    uri = base_uri + manager_uri
    response = redfishClient.get(uri)
    if response.status != 200:
        error_msg(module, "GET", uri, response.status, response.text)
    alert_uri = uri + "SnmpService/SNMPAlertDestinations/"
    snmp_res = redfishClient.get(alert_uri)
    # Get list of SNMP alert destinations
    if snmp_res.status != 200:
        error_msg(module, "GET", alert_uri, snmp_res.status, snmp_res.text)

    snmp_list = json.loads(snmp_res.text)
    for item in snmp_list["Members"]:
        # Get each alert destination details
        item_rsp = redfishClient.get(item["@odata.id"])
        if item_rsp.status != 200:
            error_msg(module, "GET", item["@odata.id"], item_rsp.status, item_rsp.text)
        # Remove @odata details
        output = remove_odata(json.loads(item_rsp.text))

        # Get SNMPv3 users details attached to alert destination
        if "SNMPv3User" in output:
            output = get_user_details(redfishClient, output, module)
        alert_destinations.append(output)
    return alert_destinations


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

    baseuri = module.params["baseuri"]
    username = module.params["username"]
    password = module.params["password"]
    http_schema = module.params["http_schema"]

    base_url = "{0}://{1}".format(http_schema, baseuri)
    redfishClient = redfish_client(
        base_url=base_url, username=username, password=password
    )
    redfishClient.login()

    alert_destinations = get_alert_destinations(redfishClient, module)

    logout(redfishClient, module)
    module.exit_json(changed=False, alert_destinations=alert_destinations)


if __name__ == "__main__":
    main()
