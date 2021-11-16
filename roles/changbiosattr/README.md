changbiosattr
=============

Changes the value of a mentioned bios attribute.

Role Variables
--------------

Credentials of the iLO like `baseuri`, `username`, `password` needs to mentioned. `bios_attribute` needs to be mentioned in form of a dictionary.

Example Playbook
----------------

An example of how to use the role: 

    - hosts: servers
      vars:
      - bios_attr: {"AdminName" : "ilohpe"}
      roles:
         - changbiosattr
         
License
-------

BSD

Author Information
------------------

Bhavya B (@Bhavya06) Hewlett Packard Enterprise 2021 
