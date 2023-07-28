Verify BIOS attributes
=========

Verify bios attributes is to verify applied bios attributes in the server

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
- hosts: servers
  vars:
    bios_attributes:
      SubNumaClustering: "Disabled"
      WorkloadProfile: "Virtualization-MaxPerformance"
  roles:
    - verify_bios_attributes
```

License
-------

BSD

Author Information
------------------

Gayathiri Devi Ramasamy (@Gayathirideviramasamy) Hewlett Packard Enterprise 2021 