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
  bios_attributes:
    required: true
    description: BIOS attributes to be verified
    type: dict
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