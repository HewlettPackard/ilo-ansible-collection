Delete Volumes
=========

Deletes volumes specified by volume IDs on a given server

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
  storage_subsystem_id:
    required: false
    description:
      - Id of the Storage Subsystem on which the volume is to be created.
    type: str
    default: ''
  volume_ids:
    required: false
    description:
      - List of IDs of volumes to be deleted.
    type: list
    default: []
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
    storage_subsystem_id: "DExxxxxx"
    volume_ids: ["volume1", "volume2"]
  roles:
     - delete_volumes
```
License
-------

BSD

Author Information
------------------

T S Kushal (@TSKushal) Hewlett Packard Enterprise 2023 
