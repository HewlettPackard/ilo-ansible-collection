get_software_inventory
======================

Stores the software inventory information of the system in a JSON output file

Role Variables
--------------

Credentials of the iLO like `baseuri`, `username`, `password` needs to mentioned.

Example Playbook
----------------

An example of how to use the role: 

    - hosts: servers
      roles:
         - get_software_inventory

License
-------

BSD

Author Information
------------------

Bhavya B (@Bhavya06) Hewlett Packard Enterprise 2021 
