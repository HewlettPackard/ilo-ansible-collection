Upload compnent
===============

Upload firmware onto the iLO server

Role Variables
--------------

Credentials of the iLO like `baseuri`, `username`, `password`, `fwpkg_file` needs to mentioned.
`force`, `update_srs`, `componentsig`, `overwrite`, `update_repository` and `update_target` are optional variables.

Example Playbook
----------------

An example of how to use the role: 

    - hosts: servers
      vars:
        - fwpkg_file: ilo5_272.fwpkg
        - update_target: False
        - update_repository: True
      roles:
         - uploadcomp

License
-------

BSD

Author Information
------------------

Bhavya B (@Bhavya06) Hewlett Packard Enterprise 2021 
