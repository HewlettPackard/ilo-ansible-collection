addiLOuseracc
=============

Creates an iLO account.

Role Variables
--------------

Credentials of the iLO - `baseuri`, `username`, `password` need to mentioned.
Details of the new account -  `new_username`, `new_password` and `roleid` need to be mentioned.

Example Playbook
----------------

An example of how to use the role: 

    - hosts: servers
      vars:
      new_username: ilouser
      new_password: ilopass12
      roleid: Administrstor
      
      roles:
         - addiLOuseracc

License
-------

BSD

Author Information
------------------

Bhavya B (@Bhavya06) Hewlett Packard Enterprise 2021 
