Verify service BIOS attributes
=========

Verify service bios attributes is to verify applied service bios attributes in the server

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
 service_attributes:
    required: true
    description: Service BIOS attributes to be verified
    type: dict
  http_schema:
    required: false
    description:
      - 'http' or 'https' Protocol
    default: https
    type: str
```
Dependencies
------------

No Dependency

Example Playbook
----------------

```
- name: Verify service bios attributes
  verify_service_bios_attributes:
    baseuri: "***.***.***.***"
    username: "abcxyz"
    password: "*****"
    service_attributes:
      ProcMonitorMwait: "Disabled"
      MemPreFailureNotification": "Enabled"
 ```     

License
-------

BSD

Author Information
------------------

Gayathiri Devi Ramasamy (@Gayathirideviramasamy) Hewlett Packard Enterprise 2021