Get Boot Settings
=========

This module will get BIOS registries from a given server

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
```

Dependencies
------------

No dependency on other modules.

Example Playbook
----------------

```
- hosts: servers
  roles:
    - get_bios_registries
```
License
-------

BSD

Author Information
------------------

T S Kushal (@TSKushal) Hewlett Packard Enterprise 2023 
