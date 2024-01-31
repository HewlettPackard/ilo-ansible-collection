Earse Physical Drives
=========

Erases physical drives on a given server


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

An example of how to use the role:

``` 
- hosts: servers
  roles:
     - erase_physical_drives
```
License
-------

BSD

Author Information
------------------

Nagendra M (@nagendram399) Hewlett Packard Enterprise 2023
