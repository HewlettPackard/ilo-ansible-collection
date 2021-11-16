UpdateRole
=========

Updates the Role id of the mentioned user.

Role Variables
--------------

Credentials of the iLO like `baseuri`, `username`, `password` needs to mentioned.
`loginname` to be mentioned for the account the user wishes to change the role id.

Example Playbook
----------------

An example of how to use the role: 

    - hosts: servers
      vars:
      loginname: ilouser
      roles:
         - UpdateRole
         
License
-------

BSD

Author Information
------------------

Bhavya B (@Bhavya06) Hewlett Packard Enterprise 2021 
