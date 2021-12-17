Create SNMP Alert Destinations
=========

This module creates SNMP alert destinations in a given server

Requirements
------------

This module requires python redfish library and ansible. You can install these packages using pip as shown below
```
pip3 install ansible==4.5.0 ansible-core==2.11.5
pip3 install redfish==3.0.2
```

Role Variables
--------------

```
  baseuri:
    required: true
    description:
      - iLO IP of the server
    type: str
  username:
    required: true
    description:
      - Username of the server for authentication
    type: str
  password:
    required: true
    description:
      - Password of the server for authentication
    type: str
  alert_destinations:
    required: true
    description:
      - List of alert destination to be added
    type: list
  destination_ip:
    required: true
    description:
      - IP address of remote management system that receives SNMP alerts
    type: str
  snmp_alert_protocol:
    required: true
    description:
      - SNMP protocol associated with the AlertDestination
      - The supported SNMP alert protocols are SNMPv1Trap, SNMPv3Trap, and SNMPv3Inform
    type: str
  trap_community:
    required: false
    description:
      - Configured SNMPv1 trap community string
    default: ""
    type: str
  security_name:
    required: false
    description:
      - SNMPv3 security name associated with SNMPv3trap or SNMPv3Inform set on SNMPAlertProtocol
      - Alphanumeric value with 1-32 characters
    default: ""
    type: str
  http_schema:
    required: false
    description:
      - 'http' or 'https' Protocol
    default: https
    type: str
```

Dependencies
------------

No dependency on other modules.

Example Playbook
----------------
```
- name: Creating SNMP alert destinations
  create_snmp_alert_destinations:
    baseuri: "***.***.***.***"
    username: "abcxyz"
    password: "******"
    alert_destinations:
      - snmp_alert_protocol: "SNMPv1Trap"
        trap_community: "public"
        destination_ip: "***.***.***.***"
        security_name: "Sec1"
```

License
-------

BSD

Author Information
------------------

Gayathiri Devi Ramasamy (@Gayathirideviramasamy) Hewlett Packard Enterprise 2021 
