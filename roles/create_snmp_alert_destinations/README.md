Create SNMP Alert Destinations
=========

This module creates SNMP alert destinations in a given server

Role Variables
--------------

```
  baseuri:
    required: true
    description:
      - iLO IP of the server
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
  cert_file:
    description:
      - absolute path to the server cert file
    type: str
  key_file:
    description:
      - absolute path to the server key file
    type: str
  alert_destinations:
    required: true
    description:
      - List of alert destination to be added
    type: list
    suboptions:
      alert_destination:
        required: true
        description:
          - IP address/hostname/FQDN of remote management system that receives SNMP alerts
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
```

Dependencies
------------

No dependency on other modules.

Example Playbook
----------------
```
  - hosts: servers
    vars:
      alert_destinations:
        - snmp_alert_protocol: "SNMPv3Trap"
          trap_community: "public"
          alert_destination: "***.***.***.***"
          security_name: "Sec1"
    roles:
       - create_snmp_alert_destinations
```

License
-------

BSD

Author Information
------------------

Gayathiri Devi Ramasamy (@Gayathirideviramasamy) Hewlett Packard Enterprise 2021 
