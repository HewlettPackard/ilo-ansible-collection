Import Trusted CA
=========

Imports Trusted CA Certificate on given server

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
  ca_file:
    required: true
    description:
      - Absolute path of the CA Certificate
    type: str
```

Dependencies
------------

No dependency

Example Playbook
----------------

```
- hosts: servers
  vars:
    ca_file: "/root/ca_file.crt"
  roles:
     - import_trusted_ca
```

License
-------

BSD

Author Information
------------------

T S Kushal (@TSKushal) Hewlett Packard Enterprise 2023 