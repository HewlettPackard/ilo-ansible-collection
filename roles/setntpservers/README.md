setNTPservers
=========

Set the NTP Servers for the iLO network.

Role Variables
--------------

Credentials of the iLO like `baseuri`, `username`, `password` need to mentioned. `attribute_name` and `attribute_value` need to be passed.

Example Playbook
----------------

An example of how to use the role: 

    - hosts: servers
      vars:
         attribute_name: StaticNTPServers
         attribute_value: 1.2.3.4
      roles:
         - setNTPservers

License
-------

BSD

Author Information
------------------

Bhavya B (@Bhavya06) Hewlett Packard Enterprise 2021 
