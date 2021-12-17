Get SNMPv3 Users
=========

This module will get SNMPv3 users from a given server

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
      - iLO IP address of the server
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
- name: Get SNMPv3 users
  get_snmpv3_users:
    baseuri: "***.***.***.***"
    username: "abcxyz"
    password: "******"
```

License
-------

BSD

Author Information
------------------

Gayathiri Devi Ramasamy (@Gayathirideviramasamy) Hewlett Packard Enterprise 2021 