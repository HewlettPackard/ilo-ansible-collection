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
  snmpv3_usernames:
    required: true
    description:
      - List of SNMPv3 user names that need to be deleted from the given server
    type: list
    elements: str
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
