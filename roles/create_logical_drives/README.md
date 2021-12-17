Create Logical Drive
=========

Creation of logical drive specified by raid_detials in a given server
 
Requirements
------------

This module requires python redfish library and ansible. You can install these packages using pip as shown below
```
pip3 install ansible==4.5.0 ansible-core==2.11.6
pip3 install redfish==3.0.2
```

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
      - List of RAID details that needs to be configured in the given server
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

No dependency

Example Playbook
----------------

```
- name: Create logical drives
  create_logical_drives:
    baseuri: "***.***.***.***"
    username: "abcxyz"
    password: "******"
    raid_details: [{"LogicalDriveName": "LD1",
                     "Raid": "Raid1",
                     "DataDrives": {
                        "DataDriveCount": 2,
                        "DataDriveMediaType": "HDD",
                        "DataDriveInterfaceType": "SAS",
                        "DataDriveMinimumSizeGiB": 0
                        }
                   }]
```
License
-------

BSD

Author Information
------------------

Varini HP (@varini-hp) Hewlett Packard Enterprise 2021 
