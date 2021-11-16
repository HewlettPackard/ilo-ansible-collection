systeminven
=========

Stores all the System inventory information of the system in a JSON output file.

Role Variables
--------------

Credentials of the iLO like `baseuri`, `username`, `password` needs to mentioned. `datatype` needs to be passed that serves as the keyword for the json file name.

Example Playbook
----------------

An example of how to use the role: 

    - hosts: servers
      vars:
         datatype: SystemInventory
      roles:
         - systeminven


License
-------

BSD

Author Information
------------------

Bhavya B (@Bhavya06) Hewlett Packard Enterprise 2021 
