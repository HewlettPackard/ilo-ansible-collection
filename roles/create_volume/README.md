Create Volume
=========

Creates volumes specified by volumes_details on a given server


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
  volume_details:
    required: true
    description:
      - Setting dict of volume to be created.
    type: dict
    suboptions:
      Name:
        required: true
        description:
          - Name of the volume to be created on the server.
        type: dict
      RAIDType:
        required: true
        description:
          - RAID Type of the volume to be created on the server.
        type: dict
      Drives:
        required: true
        description:
          - List of drives from the server to be included as part of the volume.
        type: list
```    

Dependencies
------------

No dependency on other modules.

Example Playbook
----------------

An example of how to use the role:

``` 
- hosts: servers
  vars:
    storage_subsystem_id: "DExxxxxx"
    volume_details:
      Name: "MR Volume"
      RAIDType: "RAID0"
      Drives:
        - "/redfish/v1/Systems/1/Storage/DE00B000/Drives/1"
  roles:
     - create_volume
```
License
-------

BSD

Author Information
------------------

T S Kushal (@TSKushal) Hewlett Packard Enterprise 2023
