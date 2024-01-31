Delete All Logical Drive
=========

Deleting all logical drives in a given server

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
No dependency


Example Playbook
----------------

```
- hosts: servers
  roles:
     - delete_all_logical_drives
```
License
-------

BSD

Author Information
------------------

Varni H P (@varini-hp) Hewlett Packard Enterprise 2021 
