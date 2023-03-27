setDNS
=========

Set the DNS IP for the iLO network.

Role Variables
--------------

Credentials of the iLO like `baseuri`, `username`, `password` needs to mentioned. `dns_server` IP should be provided. 
`dns_server` takes in maximum of 3 IPs. 

Example Playbook
----------------

An example of how to use the role: 

    - hosts: servers
      vars:
         dns_server: 1.1.1.1 2.2.2.2 3.3.3.3
      roles:
         - setDNS

License
-------

BSD

Author Information
------------------

Bhavya B (@Bhavya06) Hewlett Packard Enterprise 2021 
