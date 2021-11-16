Role Name
=========

Creates a session for an account. Returns the session id.

Role Variables
--------------

Credentials of the iLO like `baseuri`, `username`, `password` needs to mentioned.

Example Playbook
----------------

An example of how to use the role: 

    - hosts: servers
      vars:
      loginname: ilouser
      roles:
         - Login

License
-------

BSD

Author Information
------------------

Bhavya B (@Bhavya06) Hewlett Packard Enterprise 2021 
