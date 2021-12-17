Verify BIOS attributes
=========

Verify bios attributes is to verify applied bios attributes in the server

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
 bios_attributes:
    required: true
    description: BIOS attributes to be verified
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

No Dependency.

Example Playbook
----------------

```
- name: Verify bios attributes
  verify_bios_attributes:
    baseuri: "***.***.***.***"
    username: "abcxyz"
    password: "*****"
    bios_attributes:
      SubNumaClustering: "Disabled"
      WorkloadProfile: "Virtualization-MaxPerformance"
```

License
-------

BSD

Author Information
------------------

Gayathiri Devi Ramasamy (@Gayathirideviramasamy) Hewlett Packard Enterprise 2021 