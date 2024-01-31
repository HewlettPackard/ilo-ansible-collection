Create SNMPv3 Users
=========

This module creates SNMPv3 users in a given server

Role Variables
--------------

```
  baseuri:
    required: true
    description:
      - iLO IP of the server
    type: str
  username:
    description:
      - User for authentication with iLO.
    type: str
  password:
    description:
      - Password for authentication with iLO.
    type: str
  auth_token:
    description:
      - Security token for authentication with iLO.
    type: str
  cert_file:
    description:
      - absolute path to the server cert file
    type: str
  key_file:
    description:
      - absolute path to the server key file
    type: str
  snmpv3_users:
    required: true
    description:
      - List of SNMPv3 users to be added
    type: list
    suboptions:
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
      user_engine_id:
        required: true
        description:
          - The SNMPv3 Engine ID is the unique identifier of an SNMP engine that belongs to an SNMP agent entity
          - This value must be a hexadecimal string with an even number of 10 to 64 characters, excluding first two characters, 0x (example 0x01020304abcdef)
        type: str
```

Dependencies
------------

No dependency on other modules.

Example Playbook
----------------

```
  - hosts: servers
    vars:
      snmpv3_users:
        - security_name: "Sec1"
          auth_protocol: "SHA"
          auth_passphrase: "********"
          privacy_protocol: "AES"
          privacy_passphrase: "********"
          user_engine_id: "123450abdcef"
    roles:
       - create_snmpv3_users
```
License
-------

BSD

Author Information
------------------

Gayathiri Devi Ramasamy (@Gayathirideviramasamy) Hewlett Packard Enterprise 2021 
