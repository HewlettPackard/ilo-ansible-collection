setTimeZone
=========

Set the timezone for the iLO network.

Role Variables
--------------

Credentials of the iLO like `baseuri`, `username`, `password` need to mentioned. `attribute_value` needs to be passed.

Example Playbook
----------------

An example of how to use the role: 

    - hosts: servers
      vars:
         attribute_value: Chennai
      roles:
         - setTimeZone

License
-------

BSD

Author Information
------------------

Bhavya B (@Bhavya06) Hewlett Packard Enterprise 2021 
