configHostName
==============

Configures the hostname of an iLO network

Role Variables
--------------

Credentials of the iLO like `baseuri`, `username`, `password` needs to mentioned. `attribute_name` and `attribute_value` need to be mentioned.

Example Playbook
----------------

An example of how to use the role: 

    - hosts: servers
      vars:
      attribute_name: HostName
      attribute_value: ilohpe
      
      roles:
         - configHostName

License
-------

BSD

Author Information
------------------

Bhavya B (@Bhavya06) Hewlett Packard Enterprise 2021 
