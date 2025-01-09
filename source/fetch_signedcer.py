'''
Author: Ali Rıza Girişen 
Date: 04/01/2024 
Email: <ali.girisen@pardus.org.tr>
'''
from ldap3 import Server, Connection, SUBTREE, ALL_ATTRIBUTES
import cryptography, os, configparser, pwd, subprocess
from cryptography.x509 import load_der_x509_certificate
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone

from logger_utils import get_logger
from .request_cer import request_cer
from .update_client_ca import update_client_ca

logger = get_logger(__name__)


def fetch_signedcer(username,recursive):
    config_path = "/etc/certificate_controller/config.ini"
    if not os.path.exists(config_path):
        print("configurations has not launched")
        config_path = "config/config.ini"
        logger.error("Configurations has not found at /etc/certificate_controller/config.ini")
    if recursive >= 2:
        return False

    config = configparser.ConfigParser()
    config.read(config_path)
    ad_server = config.get('AD','ad_server')
    base_dn = config.get('AD','base_dn')
    renew_before = int(config.get('TIME','renew_before'))
    sensitive_keys_path, ticket_cache = "","" # depended user or machine account
    tmp = '/tmp'

    #client ca
    ca_path = '/usr/local/share/ca-certificates/DOMAIN-SERVER-CERTIFICATE.crt'  
    installed_cert_path = '/etc/ssl/certs/DOMAIN-SERVER-CERTIFICATE.pem'

    if not os.path.exists(installed_cert_path):
            update_client_ca(ad_server, ca_path)
    
    if "$" not in username:# $ MEANS USER IS NOT MACHINE ACCOUNT
        uid = pwd.getpwnam(username).pw_uid
        gid = pwd.getpwnam(username).pw_gid
        if uid >= 1000:
            for krb_path in os.listdir(tmp):
                if krb_path.startswith(f'krb5cc_{uid}'):
                    ticket_cache = os.path.join(tmp, krb_path)
            if ticket_cache == "":
                print("Ticket file is not existing in /tmp")
                logger.warning("Ticket(USER) file is not existing in /tmp. Creating...")
                return False

        sensitive_keys_path = f"/home/{username}/.certificate_controller/"
        permissions = 0o444
    
    else:#root computer acc
        uid = 0
        gid = 0
        sensitive_keys_path = f"/etc/ssl/.certificate_controller/"
        permissions = 0o600
        subprocess.run(["kinit","-k","-t","/etc/krb5.keytab",username])
        for krb_path in os.listdir(tmp):
            if krb_path.startswith(f'krb5cc_{uid}'):
                ticket_cache = os.path.join(tmp, krb_path)
        if ticket_cache == "":
            print("ticket was not created")
            logger.warning("Ticket(USER) file is not existing in /tmp. Creating...")
            ticket_cache = "/tmp/krb5cc_0"

        
    os.environ['KRB5CCNAME'] = f'FILE:{ticket_cache}'

    if not os.path.exists(sensitive_keys_path):
        os.makedirs(sensitive_keys_path)

    pem_file_path = f"{sensitive_keys_path}{username}.pem"
    if not os.path.exists(pem_file_path):

        server = Server(ad_server, get_info=ALL_ATTRIBUTES)
        connection = Connection(server, authentication='SASL',sasl_mechanism='GSSAPI', auto_bind=True, receive_timeout=30, auto_referrals=False, raise_exceptions=True)

        search_filter = f'(sAMAccountName={username})'
        connection.search(base_dn, search_filter, SUBTREE, attributes=['userCertificate'])

        # Parse and save the certificate as PEM file
        for entry in connection.entries:
            if entry['userCertificate']:
                for i, cert_data in enumerate(entry['userCertificate']):
                    cert = load_der_x509_certificate(cert_data, default_backend())
                    expiration_time = cert.not_valid_after_utc

                    current_date = datetime.now()
                    current_date = current_date.replace(tzinfo=timezone.utc)
                    days_remaining = (expiration_time - current_date).days

                    if days_remaining <= renew_before:
                        if os.path.exists(pem_file_path):
                            os.remove(pem_file_path)
                        request_cer(username,sensitive_keys_path,uid,gid)
                    else:
                        if not os.path.exists(pem_file_path):
                            with open(pem_file_path, "wb") as pem_file:
                                pem_file.write(cert.public_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM))
                            os.chown(pem_file_path, uid, gid)
                            os.chmod(pem_file_path, permissions)
                            print(f"Certificate Expiration Time: {expiration_time}")
                            print(f"Certificate saved as PEM: {pem_file_path}")
                            logger.info(f"Certificate Expiration Time: {expiration_time}")
                            logger.info(f"Certificate saved as PEM: {pem_file_path}")
                    break
            else:
                request_cer(username,sensitive_keys_path,uid,gid)
                fetch_signedcer(username,recursive+1)
        connection.unbind()
    else:
        with open (pem_file_path, 'rb') as f:
            cert_data = f.read()

        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        expiration_time = cert.not_valid_after_utc
        
        current_date = datetime.now()
        current_date = current_date.replace(tzinfo=timezone.utc)
        days_remaining = (expiration_time - current_date).days

        logger.info("Certificate is existing")
        if days_remaining <= renew_before:
            logger.info(f"Remaining days: {days_remaining}. Certificate is renewing...")
            request_cer(username,sensitive_keys_path,uid,gid)
            fetch_signedcer(username,recursive+1)

