setDNS
=========

Set the DNS IP for the iLO network.

Role Variables
--------------

Credentials of the iLO like `baseuri`, `username`, `password` needs to mentioned. `dns_server` IP should be provided.

Example Playbook
----------------

An example of how to use the role: 

    - hosts: servers
      vars:
         dns_server: 0.0.0.0
      roles:
         - setDNS

License
-------

BSD

Author Information
------------------

Bhavya B (@Bhavya06) Hewlett Packard Enterprise 2021 
