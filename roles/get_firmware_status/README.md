Get Firmware Status
=========

Retrives firmware status from a given iLO

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
      - Username of the server for authentication
    type: str
  password:
    required: true
    description:
      - Password of the server for authentication
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
     - get_firmware_status
```

License
-------

BSD

Author Information
------------------

Nagendra M (@nagendram399) Hewlett Packard Enterprise 2023 