# hpe.ilo  - Ansible playbooks and roles for iLOs using Redfish APIs

This repository contains the Ansible playbook samples and Ansible roles for automating the HPE server lifecycle management using iLOs.
The examples highlight the capabilities of the modules and their ability to be integrated into more complex playbooks, workflows, and applications.

These [roles](https://github.com/HewlettPackard/ilo-ansible-collection/tree/main/roles) and [playbooks](https://github.com/HewlettPackard/ilo-ansible-collection/tree/main/roles/playbooks) should give you a very good idea of how to create your own playbooks for your own needs.

Example playbooks and roles use the following collection and modules:

- [community.general](https://galaxy.ansible.com/community/general) collection - Following is the list of the modules that are being used from this collection:
    - [redfish_info](https://docs.ansible.com/ansible/latest/collections/community/general/redfish_info_module.html)
    - [redfish_command](https://docs.ansible.com/ansible/latest/collections/community/general/redfish_command_module.html)
    - [redfish_config](https://docs.ansible.com/ansible/latest/collections/community/general/redfish_config_module.html)
    - [ilo_redfish_config](https://docs.ansible.com/ansible/latest/collections/community/general/ilo_redfish_config_module.html)
    - [ilo_redfish_info](https://docs.ansible.com/ansible/latest/collections/community/general/ilo_redfish_info_module.html)

## Requirements

 - ansible >= 2.11

## Installation

To install in ansible default or defined paths use:
```
ansible-galaxy collection install hpe.ilo
```

## Ansible set up
To install Ansible and Community general package use:
```
sudo python -m pip install ansible
```
```
ansible-galaxy collection install community.general
```
```
pip install python-ilorest-library
```