deluser
=======

Deletes an iLO account.

Role Variables
--------------

Credentials of the iLO - `baseuri`, `username`, `password`, `account_username` need to mentioned.

Example Playbook
----------------

An example of how to use the role: 

    - hosts: servers
      vars:
      account_username: testuser
      
      roles:
         - deluser

License
-------

BSD

Author Information
------------------

Bhavya B (@Bhavya06) Hewlett Packard Enterprise 2021 