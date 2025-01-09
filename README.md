# Certificate-Controller
The tool stands for control certificates of debian based clients which are joined in Windows server Active Directory domains.

## Purpose
Automationing of end users ssl processes in pardus and debian based clients.

## Working Steps
- after installation, service started
- create krb ticket
- create private key and csr
- request to certificate service of AD with csr
- get root CA signed crt
- save and upload it to client
- check out signed certificate exists and available
- if it does not exist or expired renew it
all the above process tested with machine account, debian12 and windows-22 server for now.

## Getting Ready
Join AD domain as debian based client
Clone the repository


## Installation guide (for debian and debian-based systems)

Compile the deb package or install compiled one.

### Prerequisities:

Active Directory with ( IIS and Certificate Authority )

Client required packages are python3, pip, krb5-user, krb5-config, libkrb5-dev, curl, libpam-krb5 ; AS can see on requirements.txt


### Warning

Server-site ssl bindings and kerberos are mandatory.

Be aware of Server-site CA about security and permissions. There are not any permission to request certificate in fresh installed server.


## Draft 1
- Manuel executing enable


## Expected Future
- May make more solid and consistent the source code
- Basic GUI may be added for checking connection and using manual

### Troublshoot


error: externally-managed-environment
solution: sudo rm /usr/lib/python3.11/EXTERNALLY-MANAGED
