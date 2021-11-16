disableWINSReg
==============

Disables the WINS Registration for an  iLO network

Role Variables
--------------

Credentials of the iLO like `baseuri`, `username`, `password` needs to mentioned. `attribute_name` should be passed.

Example Playbook
----------------

An example of how to use the role: 

    - hosts: servers
      vars:
        - attribute_name: WINSRegistration
      roles:
         - disableWINSReg

License
-------

BSD

Author Information
------------------

Bhavya B (@Bhavya06) Hewlett Packard Enterprise 2021 
