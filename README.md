# Certificate-Controller


##Installation guide (for debian and debian-based systems)


install required packages and configure it, then join domain.

Required packages are python3, pip, krb5-user, krb5-config, libkrb5-dev, curl, libpam-krb5

Compile the deb package or install compiled one.

error: externally-managed-environment
solution: sudo rm /usr/lib/python3.11/EXTERNALLY-MANAGED


Server-site ssl bindings and kerberos are mandatory.
Be aware of Server-site CA about security and permissions. There are not any permission to request certificate in fresh installed server.
