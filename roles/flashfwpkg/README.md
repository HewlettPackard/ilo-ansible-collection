flashfwpkg
==========

Flash and upload firmware onto the server

Role Variables
--------------

Credentials of the iLO like `baseuri`, `username`, `password`, `fwpkg_file` needs to mentioned.
`force`, `tover`, `update_srs`, `componentsig`, `overwrite` are optional variables.

Example Playbook
----------------

An example of how to use the role: 

    - hosts: servers
      vars:
        - fwpkg_file: ilofw.fwpkg
      roles:
         - flashfwpkg

License
-------

BSD

Author Information
------------------

Bhavya B (@Bhavya06) Hewlett Packard Enterprise 2021 
