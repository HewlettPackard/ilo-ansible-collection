Verify UEFI Boot Order
=========

This module will verify if the input boot order matches with the server boot order or not when BiosMode is Uefi

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
- name: Verify input Boot Order against the server boot order
  verify_uefi_boot_order:
    baseuri: "***.***.***.***"
    username: "abcxyz"
    password: "******"
    uefi_boot_order: ["NIC.FlexLOM.1.1.IPv4"]
```

License
-------

BSD

Author Information
------------------

Prativa Nayak (@prativa-n) Hewlett Packard Enterprise 2021