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
    required: true
    description:
      - Username of the server for authentication
    type: str
  password:
    required: true
    description:
      - Password of the server for authentication
    type: str
  file_name:
    description: 
      - Component filename when uploading it to iLO repository
    type: str
  image_uri:
    description:
      - Webserver path where the firmware component is located.
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
    image_uri: "{{ image_url }}"
    file_name: "{{ file_name }}"
  roles:
     - update_firmware_with_upload
```

License
-------

BSD

Author Information
------------------

Nagendra M (@nagendram399) Hewlett Packard Enterprise 2023 