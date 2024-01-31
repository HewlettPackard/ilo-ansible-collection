Update With Upload
=========

Performs firmware update after uploading the firmware image to the firmware repository on a given iLO

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
  file_name:
    required: true
    description: 
      - Component filename to be uploaded to the iLO repository
    type: str
  image_uri:
    required: true
    description:
      - Webserver path where the firmware component is located
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
    image_uri: "http//10.xxx.xxx.xxx/ilo5_70.fwpkg"
    file_name: "ilo6_70.fwpkg"
  roles:
     - update_firmware_with_upload
```

License
-------

BSD

Author Information
------------------

Nagendra M (@nagendram399) Hewlett Packard Enterprise 2023 