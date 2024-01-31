Wait For iLO Reboot Completion
=========

This module waits for iLO to complete rebooting

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
  cert_file:
    description:
      - absolute path to the server cert file
    type: str
  key_file:
    description:
      - absolute path to the server key file
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
    - wait_for_ilo_reboot_completion
```
License
-------

BSD

Author Information
------------------

Gayathiri Devi Ramasamy (@Gayathirideviramasamy) Hewlett Packard Enterprise 2021 
