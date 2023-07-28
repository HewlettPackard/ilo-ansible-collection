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
    required: true
    description:
      - Username of the server for authentication
    type: str
  password:
    required: true
    description:
      - Password of the server for authentication
    type: str
  install_set_attributes:
    description: 
      - Name,description and sequence of the install set to be created
    type: dict
  maintenance_window_details: 
    description: 
      - Name,description,start and end time of maintenance window to be created
    type: dict
```

Dependencies
------------

No dependency

Example Playbook
----------------

```
- hosts: servers
  vars:
    install_set_attributes: {{ install_set_attributes }}
    maintenance_window_details: {{ maintenance_window_details }}
  roles:
     - update_firmware_through_install_set
```

License
-------

BSD

Author Information
------------------

Nagendra M (@nagendram399) Hewlett Packard Enterprise 2023 