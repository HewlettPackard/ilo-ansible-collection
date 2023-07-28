Verify UEFI Boot Order
=========

This module will verify if the input boot order matches with the server boot order or not when BiosMode is Uefi

Role Variables
--------------

```
  baseuri:
    description:
      - iLO IP of the server
    type: str
    default: NONE
    required: true
  username:
    description:
      - Username of the server for authentication
    type: str
    default: NONE
    required: true
  password:
    description:
      - Password of the server for authentication
    type: str
    default: NONE
    required: true
  http_schema:
    description:
      - http or https Protocol
    type: str
    default: https
    required: false
  uefi_boot_order:
    description:
      - Input UEFI Boot Order
    type: list
    default: NONE
    required: true
```

Dependencies
------------

No dependency on other modules.

Example Playbook
----------------

```
- hosts: servers
  vars:
    uefi_boot_order: ["NIC.FlexLOM.1.1.IPv4"]
  roles:
    - verify_uefi_boot_order
```

License
-------

BSD

Author Information
------------------

Prativa Nayak (@prativa-n) Hewlett Packard Enterprise 2021