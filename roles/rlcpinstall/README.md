rlcpinstall
============

To install Yum/Debian packages on remote host.


Role Variables
--------------

Credentials of the iLO like `baseuri`, `username`, `password` needs to mentioned. `local_file_path`, `remote_file_path` and `filename` are required variables for execution. This needs to be mentioned in the vars file.

Example Playbook
----------------

An example of how to use the role: 

    - hosts: servers
      roles:
         - rlcpinstall

License
-------

BSD

Author Information
------------------

Bhavya B (@Bhavya06) Hewlett Packard Enterprise 2021 
