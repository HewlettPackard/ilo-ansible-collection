Deluser
=========

Deletes a mentioned account

Role Variables
--------------

Credentials of the iLO like `baseuri`, `username`, `password` needs to mentioned.
`loginname` to be mentioned for the account the user wishes to delete.

Example Playbook
----------------

An example of how to use the role: 

    - hosts: servers
      vars:
      loginname: ilouser
      roles:
         - Deluser
         
License
-------

BSD

Author Information
------------------

Bhavya B (@Bhavya06) Hewlett Packard Enterprise 2021 
