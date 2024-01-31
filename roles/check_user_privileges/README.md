Check User Privileges
=========

This module checks privileges of a user on a given server

Role Variables
--------------

```
  baseuri:
    required: true
    description:
      - iLO IP address of the server
    type: str
  auth_token:
    required: true
    description:
      - Security token for authentication with iLO.
    type: str
  required_permissions:
    required: true
    description:
      - permissions to be checked against provided user
    type: list
    elements: str
    default: ['HostBIOSConfigPriv', 'HostNICConfigPriv', 'HostStorageConfigPriv']
```

Dependencies
------------

No dependency on other modules.

Example Playbook
----------------

```
- hosts: servers
  vars:
    required_permissions: ['HostBIOSConfigPriv']
  roles:
    - check_user_privileges
```

License
-------

BSD

Author Information
------------------

T S Kushal (@TSKushal) Hewlett Packard Enterprise 2023 