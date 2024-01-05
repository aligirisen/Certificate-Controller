'''
Author: Ali Rıza Girişen 
Date: 04/01/2024 
Email: <ali.girisen@pardus.org.tr>
'''
from ldap3 import Server, Connection, SUBTREE, ALL_ATTRIBUTES
import cryptography, os, configparser
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from request_cer import request_cer


def fetch_signedcer():
    config_path = "/etc/certificate_controller/config.ini"
    if os.path.exists(config_path):
        pass
    else:
        config_path = "config/config.ini"

    config = configparser.ConfigParser()
    config.read(config_path)
    ad_server = config.get('AD','ad_server')
    ad_username = config.get('AD','ad_username')
    ad_password = config.get('AD','ad_password')
    base_dn = config.get('AD','base_dn')
    user_to_query = config.get('AD','entry_to_query')
    renew_before = int(config.get('TIME','renew_before'))

    server = Server(ad_server, get_info=ALL_ATTRIBUTES, use_ssl=True)
    connection = Connection(server, user=ad_username, password=ad_password, auto_bind=True, receive_timeout=30, auto_referrals=False, raise_exceptions=True)

    search_filter = f'(sAMAccountName={user_to_query})'
    connection.search(base_dn, search_filter, SUBTREE, attributes=['userCertificate'])

    # Parse and save the certificate as PEM file
    for entry in connection.entries:
        for i, cert_data in enumerate(entry['userCertificate']):
            cert = load_der_x509_certificate(cert_data, default_backend())
            expiration_time = cert.not_valid_after

            current_date = datetime.now()
            days_remaining = (cert.not_valid_after - current_date).days

            if days_remaining <= renew_before:
                request_cer()
            else:
                pem_file_path = f"{user_to_query}_signed_certificate{i + 1}.pem"
                with open(pem_file_path, "wb") as pem_file:
                    pem_file.write(cert.public_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM))
                print(f"Certificate Expiration Time: {expiration_time}")
                print(f"Certificate saved as PEM: {pem_file_path}")
            break
    connection.unbind()
fetch_signedcer()
