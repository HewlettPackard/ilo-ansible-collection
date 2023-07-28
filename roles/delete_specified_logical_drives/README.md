Delete Specified Logical Drive
=========

Deleting specified logical drives in a given server

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
  logical_drives_names:
    description:
      - logical drives names which are to be deleted
    type: list
    elements: str
  http_schema:
    required: false
    description:
      - 'http' or 'https' Protocol
    default: https
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
    logical_drives_names: ["LD1", "LD2"]
  roles:
     - delete_specified_logical_drives
```
License
-------

BSD

Author Information
------------------

Varni H P (@varini-hp) Hewlett Packard Enterprise 2021 
