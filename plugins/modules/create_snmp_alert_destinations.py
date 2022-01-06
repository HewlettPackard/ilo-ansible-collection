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
module: create_snmp_alert_destinations
description: This module creates SNMP alert destinations in the server
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
  alert_destinations:
    description:
      - List of alert destination that needs to be added in the given server
    type: list
    default: NONE
    required: true
  destination_ip:
    description:
      - IP address of remote management system that receives SNMP alerts
    type: str
    default: NONE
    required: true
  snmp_alert_protocol:
    description:
      - SNMP protocol associated with the AlertDestination
      - The supported SNMP alert protocols are SNMPv1Trap, SNMPv3Trap, and SNMPv3Inform
    type: str
    default: NONE
    required: true
  trap_community:
    description:
      - Configured SNMPv1 trap community string
    type: str
    default: NONE
    required: false
  security_name:
    description:
      - SNMPv3 security name associated with SNMPv3trap or SNMPv3Inform set on SNMPAlertProtocol
      - Alphanumeric value with 1-32 characters
      - It is mandatory field for SNMPv3Trap and SNMPv3Inform protocol and not required for SNMPv1Trap protocol
      - Provided security_name must be already existing in the server
    type: str
    default: NONE
    required: false
  http_schema:
    description:
      - http or https Protocol
    type: str
    default: https
    required: false
"""

EXAMPLES = r"""
- name: Creating SNMP alert destinations
  create_snmp_alert_destinations:
    baseuri:  "***.***.***.***"
    username: "abcxzy"
    password: "******"
    alert_destinations:
      - snmp_alert_protocol: "SNMPv1Trap"
        trap_community: "public"
        destination_ip: "***.***.***.***"
        security_name: "Sec1"
"""

RETURN = r"""
  expected_result:
    description: SNMP alert destinations are created in the server
    returned: SNMP AlertDestinations are added
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
    returned: GET on /redfish/v1/Managers/1/SnmpService/SNMPAlertDestinations/<alert_destination ID>/ Failed, Status <Status code>,
     Response <API response>
    corrective_action: Verify the response in the output message
    type: str
  failure case 7:
    description: Maximum alert destinations in the server reached
    returned: Maximum of 8 alert destinations can be added to a server. Already server has <number of existing alert destinations in server>
     Alertdestinations and provided <number of alert destinations provided as input> more Alertdestinations
    corrective_action: Validate the input to provide the correct number of SNMP alert destinations
    type: str
  failure case 8:
    description: Input parameter is missing
    returned: Input parameter <paramater> is missing to create alert destination
    corrective_action: Validate the input
    type: str
  failure case 9:
    description: Invalid alert destination IP address
    returned: Invalid IP address <destination IP address>
    corrective_action: Validate the input alert destination IP address
    type: str
  failure case 10:
    description: Wrong snmp alert protocol provided
    returned: Wrong SNMP Alert protocol <Protocol name> is provided
    corrective_action: Validate the input
    type: str
  failure case 11:
    description: security_name is missing
    returned: security_name is missing for SNMP Alert protocol <SNMPAlertProtocol>, destination IP <destination IP address>
    corrective_action: Validate the input
    type: str
  failure case 12:
    description: Adding SNMP AlertDestination failed
    returned: Adding SNMP AlertDestination <destination IP address> failed, Status <Status code>, Response <API response>
    corrective_action: Verify the response in the output message
    type: str
"""

import json
import ipaddress

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


def get_alert_destinations(redfishClient, module):
    # Get on Managers API
    alert_destinations = []
    uri = base_uri + manager_uri
    response = redfishClient.get(uri)
    if response.status != 200:
        error_msg(module, "GET", uri, response.status, response.text)
    snmp_res = redfishClient.get(uri + "SnmpService/SNMPAlertDestinations/")
    if snmp_res.status != 200:
        error_msg(
            module,
            "GET",
            uri + "SnmpService/SNMPAlertDestinations/",
            snmp_res.status,
            snmp_res.text,
        )
    snmp_list = json.loads(snmp_res.text)
    for item in snmp_list["Members"]:
        item_rsp = redfishClient.get(item["@odata.id"])
        if item_rsp.status != 200:
            error_msg(module, "GET", item["@odata.id"], item_rsp.status, item_rsp.text)
        alert_destinations.append(json.loads(item_rsp.text))
    return alert_destinations


def validate_alert_destinations(server_alert_destinations, alert_destinations, module):
    # Validating input parameters
    if len(server_alert_destinations) + len(alert_destinations) > 8:
        message = (
            "Maximum of 8 alert destinations can be added to a server..."
            + "Already server has %s Alertdestinations and provided %s more Alertdestinations"
        )
        module.fail_json(
            msg=message % (len(server_alert_destinations), len(alert_destinations))
        )
    input_list = ["destination_ip", "snmp_alert_protocol"]
    for dest in alert_destinations:
        for input in input_list:
            if input not in dest.keys():
                module.fail_json(
                    msg="Input parameter '%s' is missing to create alert destination"
                    % input
                )
        try:
            ipaddress.ip_address(dest["destination_ip"])
        except Exception as e:
            module.fail_json(msg="Invalid IP address: %s" % dest["destination_ip"])
        if dest["snmp_alert_protocol"].lower() == "snmpv1trap":
            dest["snmp_alert_protocol"] = "SNMPv1Trap"
        elif dest["snmp_alert_protocol"].lower() == "snmpv3trap":
            dest["snmp_alert_protocol"] = "SNMPv3Trap"
        elif dest["snmp_alert_protocol"].lower() == "snmpv3inform":
            dest["snmp_alert_protocol"] = "SNMPv3Inform"
        else:
            module.fail_json(
                msg="Wrong SNMP Alert protocol '%s' is provided"
                % dest["snmp_alert_protocol"]
            )
        if "trap_community" not in dest or dest["trap_community"].lower() in [
            "na",
            " ",
        ]:
            dest["trap_community"] = ""
        if dest["snmp_alert_protocol"] in ["SNMPv3Trap", "SNMPv3Inform"] and (
            "security_name" not in dest or not dest["security_name"]
        ):
            module.fail_json(
                msg="security_name is missing for SNMP Alert protocol: '%s', destination IP: '%s'"
                % (dest["snmp_alert_protocol"], dest["destination_ip"])
            )
    return alert_destinations


def create_alert_destination(redfishClient, dest, module):
    # Define payload
    body = {
        "AlertDestination": dest["destination_ip"],
        "SNMPAlertProtocol": dest["snmp_alert_protocol"],
        "TrapCommunity": dest["trap_community"],
    }
    # Adding SNMP username to Payload for SNMPv3Trap/SNMPv3Inform
    if dest["snmp_alert_protocol"] in ["SNMPv3Trap", "SNMPv3Inform"]:
        body["SecurityName"] = dest["security_name"]
    # POST on Managers API
    uri = base_uri + manager_uri + "SnmpService/SNMPAlertDestinations/"
    snmp_res = redfishClient.post(uri, body=body)
    if snmp_res.status != 201:
        module.fail_json(
            msg="Adding SNMP AlertDestination %s failed, status: %s, response: %s, API: %s"
            % (dest["destination_ip"], str(snmp_res.status), snmp_res.text, uri)
        )


def main():
    module = AnsibleModule(
        argument_spec=dict(
            baseuri=dict(required=True, type="str"),
            username=dict(required=True, type="str"),
            password=dict(required=True, type="str", no_log=True),
            alert_destinations=dict(required=True, type="list"),
            http_schema=dict(required=False, default="https", type="str"),
        )
    )

    if not HAS_REDFISH:
        module.fail_json(msg=missing_required_lib("redfish"))

    baseuri = module.params["baseuri"]
    username = module.params["username"]
    password = module.params["password"]
    alert_destinations = module.params["alert_destinations"]
    http_schema = module.params["http_schema"]

    base_url = "{0}://{1}".format(http_schema, baseuri)
    redfishClient = redfish_client(
        base_url=base_url, username=username, password=password
    )
    redfishClient.login()

    server_alert_destinations = get_alert_destinations(redfishClient, module)
    alert_destinations = validate_alert_destinations(
        server_alert_destinations, alert_destinations, module
    )

    for dest in alert_destinations:
        create_alert_destination(redfishClient, dest, module)

    logout(redfishClient, module)
    module.exit_json(changed=True, msg="SNMP AlertDestinations are added")


if __name__ == "__main__":
    main()
