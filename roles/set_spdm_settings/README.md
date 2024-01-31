Set SPDM Settings
=========

Set SPDM settings on a given server

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
  spdm_settingss:
    required: true
    description:
      - Dictionary with values of SPDM parameters to be configured in the given server
    type: dict
    suboptions:
      global_component_integrity:
        required: true
        description:
          - Values of GlobalComponentIntegrity parameter to be configured on the given server.
        type: str
        choices: ['Enabled', 'Disabled']
      component_integrity_policy:
        required: true
        description:
          - Values of ComponentIntegrityPolicy parameter to be configured on the given server.
        type: str
        choices: ['NoPolicy', 'HaltBootOnSPDMFailure']
```

Dependencies
------------

No dependency

Example Playbook
----------------

```
- hosts: servers
  vars:
    spdm_settings:
      global_component_integrity: "Enabled"
      component_integrity_policy: "NoPolicy" 
  roles:
     - set_spdm_settings
```

License
-------

BSD

Author Information
------------------

T S Kushal (@TSKushal) Hewlett Packard Enterprise 2021 