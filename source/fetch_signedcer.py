'''
Author: Ali Rıza Girişen 
Date: 04/01/2024 
Email: <ali.girisen@pardus.org.tr>
'''
from ldap3 import Server, Connection, SUBTREE, ALL_ATTRIBUTES
import cryptography, os, configparser, pwd
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from request_cer import request_cer
from update_client_ca import update_client_ca


def fetch_signedcer():
    config_path = "/etc/certificate_controller/config.ini"
    if os.path.exists(config_path):
        pass
    else:
        config_path = "config/config.ini"

    config = configparser.ConfigParser()
    config.read(config_path)
    ad_server = config.get('AD','ad_server')
    base_dn = config.get('AD','base_dn')
    user_to_query = config.get('KRB','entry_to_query')
    renew_before = int(config.get('TIME','renew_before'))
    username = os.getlogin()
    username = os.environ.get('SUDO_USER')
    sensitive_keys_path = "" # depended user or machine account

    #client ca
    ca_path = '/usr/local/share/ca-certificates/DOMAIN-SERVER-CERTIFICATE.crt'  
    installed_cert_path = '/etc/ssl/certs/DOMAIN-SERVER-CERTIFICATE.pem'

    print(username)
    uid = pwd.getpwnam(username).pw_uid
    print(uid)
    gid = pwd.getpwnam(username).pw_gid
    print(gid)

    directories = ["/etc/ssl/.certificate_controller",f"/home/{username}/.certificate_controller"]
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)


    if not os.path.exists(installed_cert_path):
            update_client_ca(ad_server, ca_path)
    

    if "$" not in user_to_query:# $ MEANS USER IS NOT MACHINE ACCOUNT
        uid = pwd.getpwnam(username).pw_uid
        ticket_cache = f'/tmp/krb5cc_{uid}'
        os.environ['KRB5CCNAME'] = f'FILE:{ticket_cache}'
        sensitive_keys_path = f"/home/{username}/.certificate_controller/"
        permissions = 0o444
    else:#root computer acc
        uid = 0
        gid = 0
        sensitive_keys_path = f"/etc/ssl/.certificate_controller/"
        permissions = 0o600

    server = Server(ad_server, get_info=ALL_ATTRIBUTES)
    connection = Connection(server, authentication='SASL',sasl_mechanism='GSSAPI', auto_bind=True, receive_timeout=30, auto_referrals=False, raise_exceptions=True)

    search_filter = f'(sAMAccountName={user_to_query})'
    connection.search(base_dn, search_filter, SUBTREE, attributes=['userCertificate'])

    # Parse and save the certificate as PEM file
    for entry in connection.entries:
        if entry['userCertificate']:
            for i, cert_data in enumerate(entry['userCertificate']):
                cert = load_der_x509_certificate(cert_data, default_backend())
                expiration_time = cert.not_valid_after

                current_date = datetime.now()
                days_remaining = (cert.not_valid_after - current_date).days

                pem_file_path = f"{sensitive_keys_path}{user_to_query}.pem"
                print("Checking...")

                if days_remaining <= renew_before:
                    if os.path.exists(pem_file_path):
                        os.remove(pem_file_path)
                    request_cer(sensitive_keys_path,uid,gid)
                else:
                    if not os.path.exists(pem_file_path):
                        with open(pem_file_path, "wb") as pem_file:
                            pem_file.write(cert.public_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM))
                        os.chown(pem_file_path, uid, gid)
                        os.chmod(pem_file_path, permissions)
                        print(f"Certificate Expiration Time: {expiration_time}")
                        print(f"Certificate saved as PEM: {pem_file_path}")
                break
        else:
            request_cer(sensitive_keys_path,uid,gid)

    connection.unbind()
