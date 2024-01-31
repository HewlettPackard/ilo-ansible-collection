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
  uefi_boot_order:
    required: true
    description:
      - Input UEFI Boot Order
    type: list
    default: NONE
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