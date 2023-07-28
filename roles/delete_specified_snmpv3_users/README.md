Delete Specified SNMPv3 Users
=========

Deleting specified SMNPv3 users in a given server

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
  snmpv3_usernames:
    description:
      - List of SNMPv3 user names that need to be deleted from the given server
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
    snmpv3_usernames:
      - user1
      - user2
  roles:
     - delete_specified_snmpv3_users
```
License
-------

BSD

Author Information
------------------

Varni H P (@varini-hp) Hewlett Packard Enterprise 2021 
