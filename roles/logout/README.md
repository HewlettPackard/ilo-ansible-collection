Logout
=========

Deletes the session created by the Login role. 

Role Variables
--------------

Credential of the iLO - `baseuri` needs to mentioned. Other variables `auth_token`and `session_uri` need to passed from variable returned by the logout role.

Dependencies
------------

Login role should be executed before the logout role.

Example Playbook
----------------

An example of how to use the role: 

    - hosts: servers
      vars:
      loginname: ilouser
      roles:
         - Logout

License
-------

BSD

Author Information
------------------

Bhavya B (@Bhavya06) Hewlett Packard Enterprise 2021 
