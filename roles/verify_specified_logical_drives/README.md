Verify Specified Logical Drives
=========

Verifying specified logical drives details in a given server

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
  raid_details:
    required: true
    description:
      - RAID details that need to be verified in the given server
    type: list
  http_schema:
    required: false
    description:
      - 'http' or 'https' Protocol
    default: https
    type: str
```
Dependencies
------------

No Dependency

Example Playbook
----------------

```
- hosts: servers
  vars:
    raid_details:
      - LogicalDriveName: LD1
        Raid: Raid1
        DataDrives:
            DataDriveCount: 2
            DataDriveMediaType: HDD
            DataDriveInterfaceType: SAS
            DataDriveMinimumSizeGiB: 0
  roles:
    - verify_specified_logical_drives
```

License
-------

BSD

Author Information
------------------

Varni H P (@varini-hp) Hewlett Packard Enterprise 2021