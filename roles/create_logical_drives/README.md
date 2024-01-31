Create Logical Drives
=========

Creates logical drives specified by raid_details in a given server


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
  raid_details:
    required: true
    description:
      - List of RAID details that need to be configured in the given server.
    type: list
    elements: dict
    suboptions:
      LogicalDriveName:
        required: true
        description:
          - Logical drive name that needs to be configured in the given server
        type: str
      Raid:
        required: true
        description:
          - Type of RAID
        type: str
      DataDrives:
        required: true
        description:
          - Specifies the data drive details like media type, interface type, disk count and size
        type: dict
      DataDriveCount:
        required: true
        description:
          - Number of physical drives that is required to create specified RAID
        type: int
      DataDriveMediaType:
        required: true
        description:
          - Media type of the disk
        type: str
      DataDriveInterfaceType:
        required: true
        description:
          - Interface type of the disk
        type: str
      DataDriveMinimumSizeGiB:
        required: true
        description:
          - Minimum size required in the physical drive
        type: int
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
    raid_details: 
      - LogicalDriveName: "LD1"
        Raid: "Raid1"
        DataDrives:
          DataDriveCount: 2
          DataDriveMediaType: "HDD"
          DataDriveInterfaceType: "SAS"
          DataDriveMinimumSizeGiB: 0
  roles:
     - create_logical_drives
```
License
-------

BSD

Author Information
------------------

Varini HP (@varini-hp) Hewlett Packard Enterprise 2021 
