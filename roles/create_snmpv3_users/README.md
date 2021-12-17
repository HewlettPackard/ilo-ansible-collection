Create SNMPv3 Users
=========

This module creates SNMPv3 users in a given server

Requirements
------------

This module requires python redfish library and ansible. You can install these packages using pip as shown below
```
pip3 install ansible==4.5.0 ansible-core==2.11.5
pip3 install redfish==3.0.2
```

Role Variables
--------------

```
  baseuri:
    required: true
    description:
      - iLO IP of the server
    type: str
  username:
    required: true
    description:
      - Username of the server for authentication
    type: str
  password:
    required: true
    description:
      - Password of the server for authentication
    type: str
  snmpv3_users:
    required: true
    description:
      - List of SNMPv3 users to be added
    type: list
  security_name:
    required: true
    description:
      - SNMPv3 security name associated with SNMPv3trap or SNMPv3Inform set on SNMPAlertProtocol
      - Alphanumeric value with 1-32 characters
    type: str
  auth_protocol:
    required: true
    description:
      - Sets the message digest algorithm to use for encoding the authorization passphrase
      - The message digest is calculated over an appropriate portion of an SNMP message and is included as part of the message sent to the recipient
      - Supported Auth protocols are MD5, SHA, and SHA256
    type: str
  auth_passphrase:
    required: true
    description:
      - Sets the passphrase to use for sign operations
      - String with 8-49 characters
    type: str
  privacy_protocol:
    required: true
    description:
      - Sets the encryption algorithm to use for encoding the privacy passphrase
      - A portion of an SNMP message is encrypted before transmission
      - Supported privacy protocols are AES and DES
    type: str
  privacy_passphrase:
    required: true
    description:
      - Sets the passphrase to use for encrypt operations
      - String with 8-49 characters
    type: str
  http_schema:
    required: false
    description:
      - 'http' or 'https' Protocol
    default: https
    type: str
```

Dependencies
------------

No dependency on other modules.

Example Playbook
----------------

```
- name: Creating SNMPv3 users
  create_snmpv3_users:
    baseuri:  "***.***.***.***"
    username: "abcxyz"
    password: "******"
    snmpv3_users:
      - security_name: "Sec1"
        auth_protocol: "SHA"
        auth_passphrase: "********"
        privacy_protocol: "AES"
        privacy_passphrase: "********"
```
License
-------

BSD

Author Information
------------------

Gayathiri Devi Ramasamy (@Gayathirideviramasamy) Hewlett Packard Enterprise 2021 
