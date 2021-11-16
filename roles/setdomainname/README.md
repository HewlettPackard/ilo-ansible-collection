setDomainName
=========

Set the Domain name for an iLO network

Role Variables
--------------

Credentials of the iLO like `baseuri`, `username`, `password` needs to mentioned. `domain_name` needs to be passed.

Example Playbook
----------------

An example of how to use the role: 

    - hosts: servers
      vars:
         domain_name: ilohpe
      roles:
         - setDomainName
License
-------

BSD

Author Information
------------------

Bhavya B (@Bhavya06) Hewlett Packard Enterprise 2021 
