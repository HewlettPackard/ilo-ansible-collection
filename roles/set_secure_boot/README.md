Set Secure Boot
=========

Sets Secure Boot on a given server


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
  secure_boot_enable:
    required: false
    description:
      - Setting parameter to enable or disable SecureBoot.
    type: bool
    default: True
```    

Dependencies
------------

No dependency on other modules.

Example Playbook
----------------

An example of how to use the role:

``` 
- hosts: servers
  vars:
    secure_boot_enable: True
  roles:
     - set_secure_boot
```
License
-------

BSD

Author Information
------------------

Varini HP (@varini-hp) Hewlett Packard Enterprise 2021 
