Update Firmware through Install Set
=========

Performs firmware update through install set on a given iLO

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
  install_set_attributes:
    required: true
    description: 
      - Name, description and sequence of the install set to be created
    type: dict
    suboptions:
      install_set_name:
        required: true
        description: 
          - Name of the install set
        type: str
      Install_set_sequence:
        required: true
        description: 
          - List of firmwares to be installed
        type: list
        suboptions:
          Name:
            required: true
            description: 
              - Name of the task
            type: str
          Filename:
            required: true
            description: 
              - Firmware component filename present in the iLO repository
            type: str
          UpdatableBy:
            description: 
              - List of update agents
            type: list
            default: Bmc
            elements: str
      Description:
        description: 
          - Description of the install set
        type: str
  maintenance_window_details:
    required: true
    description: 
      - Name, description, start and end time of maintenance window to be created
    type: dict
    suboptions:
      Name:
        required: true
        description: 
          - Name of the maintenance window
        type: str
      Description:
        description: 
          - Description of maintenance window
        type: str
      StartAfter:
        description: 
          - Start time of the maintenance window
        type: str
      Expire:
        description: 
          - End time of the maintenance window
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
    install_set_attributes:
      Name: nfv
      Install_set_sequence:
        - Name: nfv
          Filename: ilo5_278.fwpkg
          UpdatableBy:
            - Bmc
      Description: nfv
    maintenance_window_details:
      Description: nfv
      Name: test
      StartAfter: '2023-10-09T18:38:00Z'
      Expire: '2023-10-10T18:38:00Z'
  roles:
     - update_firmware_through_install_set
```

License
-------

BSD

Author Information
------------------

Nagendra M (@nagendram399) Hewlett Packard Enterprise 2023 