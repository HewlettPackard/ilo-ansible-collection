Map User Certificate
=========

Maps a Certificate to a specified User on a given server

Role Variables
--------------

```
  baseuri:
    required: true
    description:
      - iLO IP of the server
    type: str
  username:
    required: true
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
  user_cert_file:
    required: true
    description:
      - Absolute path of the User Certificate
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
    user_cert_file: "/root/user_certificate_file.crt"
  roles:
     - map_user_certificate
```

License
-------

BSD

Author Information
------------------

T S Kushal (@TSKushal) Hewlett Packard Enterprise 2021 