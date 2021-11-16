setonetimeboot
=========

Sets a one time boot to the mentioned bootdevice. This function only works when the bootmode is set to legacy bios.

Role Variables
--------------

Credentials of the iLO like `baseuri`, `username`, `password` needs to mentioned. `bootdevice` needs to be passed.

Example Playbook
----------------

An example of how to use the role: 

    - hosts: servers
      vars:
         bootdevice: Pxe
      roles:
         - setonetimeboot

License
-------

BSD

Author Information
------------------

Bhavya B (@Bhavya06) Hewlett Packard Enterprise 2021 
