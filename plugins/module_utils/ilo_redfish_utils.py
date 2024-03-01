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

from ansible_collections.community.general.plugins.module_utils.redfish_utils import (
    RedfishUtils,
)


class iLORedfishUtils(RedfishUtils):
    def get_ilo_sessions(self):
        result = {}
        # listing all users has always been slower than other operations, why?
        session_list = []
        sessions_results = []
        # Get these entries, but does not fail if not found
        properties = ["Description", "Id", "Name", "UserName"]

        # Changed self.sessions_uri to Hardcoded string.
        response = self.get_request(
            self.root_uri + self.service_root + "SessionService/Sessions/"
        )
        if not response["ret"]:
            return response
        result["ret"] = True
        data = response["data"]

        if "Oem" in data:
            if 'Hp' in data["Oem"]:
                data["Oem"]["Hpe"] = data["Oem"]["Hp"]
            if data["Oem"]["Hpe"]["Links"]["MySession"]["@odata.id"]:
                current_session = data["Oem"]["Hpe"]["Links"]["MySession"]["@odata.id"]

        for sessions in data[u"Members"]:
            # session_list[] are URIs
            session_list.append(sessions[u"@odata.id"])
        # for each session, get details
        for uri in session_list:
            session = {}
            if uri != current_session:
                response = self.get_request(self.root_uri + uri)
                if not response["ret"]:
                    return response
                data = response["data"]
                for property in properties:
                    if property in data:
                        session[property] = data[property]
                sessions_results.append(session)
        result["msg"] = sessions_results
        result["ret"] = True
        return result

    def set_ntp_server(self, mgr_attributes):
        result = {}
        setkey = mgr_attributes['mgr_attr_name']

        nic_info = self.get_manager_ethernet_uri()
        ethuri = nic_info["nic_addr"]

        response = self.get_request(self.root_uri + ethuri)
        if not response['ret']:
            return response
        result['ret'] = True
        data = response['data']
        payload = {"DHCPv4": {
            "UseNTPServers": ""
        }}

        if data["DHCPv4"]["UseNTPServers"]:
            payload["DHCPv4"]["UseNTPServers"] = False
            res_dhv4 = self.patch_request(self.root_uri + ethuri, payload)
            if not res_dhv4['ret']:
                return res_dhv4

        payload = {"DHCPv6": {
            "UseNTPServers": ""
        }}

        if data["DHCPv6"]["UseNTPServers"]:
            payload["DHCPv6"]["UseNTPServers"] = False
            res_dhv6 = self.patch_request(self.root_uri + ethuri, payload)
            if not res_dhv6['ret']:
                return res_dhv6

        datetime_uri = self.manager_uri + "DateTime"

        listofips = mgr_attributes['mgr_attr_value'].split(" ")
        if len(listofips) > 2:
            return {'ret': False, 'changed': False, 'msg': "More than 2 NTP Servers mentioned"}

        ntp_list = []
        for ips in listofips:
            ntp_list.append(ips)

        while len(ntp_list) < 2:
            ntp_list.append("0.0.0.0")

        payload = {setkey: ntp_list}

        response1 = self.patch_request(self.root_uri + datetime_uri, payload)
        if not response1['ret']:
            return response1

        return {'ret': True, 'changed': True, 'msg': "Modified %s" % mgr_attributes['mgr_attr_name']}

    def set_time_zone(self, attr):
        key = attr["mgr_attr_name"]

        uri = self.manager_uri + "DateTime/"
        response = self.get_request(self.root_uri + uri)
        if not response["ret"]:
            return response

        data = response["data"]

        if key not in data:
            return {"ret": False, "changed": False, "msg": "Key %s not found" % key}

        timezones = data["TimeZoneList"]
        index = ""
        for tz in timezones:
            if attr["mgr_attr_value"] in tz["Name"]:
                index = tz["Index"]
                break

        payload = {key: {"Index": index}}
        response = self.patch_request(self.root_uri + uri, payload)
        if not response["ret"]:
            return response

        return {
            "ret": True,
            "changed": True,
            "msg": "Modified %s" % attr["mgr_attr_name"],
        }

    def set_dns_server(self, attr):
        key = attr['mgr_attr_name']
        nic_info = self.get_manager_ethernet_uri()
        uri = nic_info["nic_addr"]

        listofips = attr['mgr_attr_value'].split(" ")
        if len(listofips) > 3:
            return {'ret': False, 'changed': False, 'msg': "More than 3 DNS Servers mentioned"}

        dns_list = []
        for ips in listofips:
            dns_list.append(ips)

        while len(dns_list) < 3:
            dns_list.append("0.0.0.0")

        payload = {
            "Oem": {
                "Hpe": {
                    "IPv4": {
                        key: dns_list
                    }
                }
            }
        }

        response = self.patch_request(self.root_uri + uri, payload)
        if not response['ret']:
            return response

        return {'ret': True, 'changed': True, 'msg': "Modified %s" % attr['mgr_attr_name']}

    def set_domain_name(self, attr):
        key = attr["mgr_attr_name"]

        nic_info = self.get_manager_ethernet_uri()
        ethuri = nic_info["nic_addr"]

        response = self.get_request(self.root_uri + ethuri)
        if not response["ret"]:
            return response

        data = response["data"]

        payload = {"DHCPv4": {"UseDomainName": ""}}

        if data["DHCPv4"]["UseDomainName"]:
            payload["DHCPv4"]["UseDomainName"] = False
            res_dhv4 = self.patch_request(self.root_uri + ethuri, payload)
            if not res_dhv4["ret"]:
                return res_dhv4

        payload = {"DHCPv6": {"UseDomainName": ""}}

        if data["DHCPv6"]["UseDomainName"]:
            payload["DHCPv6"]["UseDomainName"] = False
            res_dhv6 = self.patch_request(self.root_uri + ethuri, payload)
            if not res_dhv6["ret"]:
                return res_dhv6

        domain_name = attr["mgr_attr_value"]

        payload = {"Oem": {"Hpe": {key: domain_name}}}

        response = self.patch_request(self.root_uri + ethuri, payload)
        if not response["ret"]:
            return response
        return {
            "ret": True,
            "changed": True,
            "msg": "Modified %s" % attr["mgr_attr_name"],
        }

    def set_wins_registration(self, mgrattr):
        Key = mgrattr["mgr_attr_name"]

        nic_info = self.get_manager_ethernet_uri()
        ethuri = nic_info["nic_addr"]

        payload = {"Oem": {"Hpe": {"IPv4": {Key: False}}}}

        response = self.patch_request(self.root_uri + ethuri, payload)
        if not response["ret"]:
            return response
        return {
            "ret": True,
            "changed": True,
            "msg": "Modified %s" % mgrattr["mgr_attr_name"],
        }
