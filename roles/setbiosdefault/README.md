setbiosdefault
=========

Sets the values of all bios attributes to default values.

Role Variables
--------------

Credentials of the iLO like `baseuri`, `username`, `password` needs to mentioned.

Example Playbook
----------------

An example of how to use the role: 

    - hosts: servers
      roles:
         - setbiosdefault

License
-------

BSD

Author Information
------------------

Bhavya B (@Bhavya06) Hewlett Packard Enterprise 2021 
