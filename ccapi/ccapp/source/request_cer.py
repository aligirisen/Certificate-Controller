'''
Author: Ali Rıza Girişen 
Date: 04/01/2024 
Email: <ali.girisen@pardus.org.tr>
'''
import requests,os,configparser
from requests_kerberos import HTTPKerberosAuth
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
import base64
from cryptography.x509.oid import NameOID

def request_cer(username,sensitive_keys_path,uid,gid):
    config_path = "/etc/certificate_controller/config.ini"
    if os.path.exists(config_path):
        pass
    else:
        print("Certificate-Controller is not installed")
        config_path = "config/config.ini"
    #variables
    config = configparser.ConfigParser()
    config.read(config_path)
    ca_cert_path = config.get('KRB','ca_cert_path')
    template_name = config.get('KRB','template_name')
    certsrv_url = config.get('KRB','certsrv_url')
    
    server = config.get('AD', 'ad_server')
    private_key_path, csr_path, csr_content = "","",""

    #parse domain from server
    server = server.upper()
    domain_parts = server.split('.')
    domain = '.'.join(domain_parts[-2:])
    kerberos_principal = f'{username}@{domain}'

    private_key_path = f'{sensitive_keys_path}private_key.pem'
    csr_path = f'{sensitive_keys_path}csr.csr'

    if os.path.exists(csr_path):
        with open(csr_path, "r") as csr_file:
            csr_content = csr_file.read()
    else:
        private_key = generate_private_key_pem(private_key_path,uid,gid)
        generate_csr(username, private_key, csr_path)

    # Kerberos authentication using keytab
    os.environ['KRB5CCNAME'] = f'/tmp/krb5cc_{uid}'
    kerberos_auth = HTTPKerberosAuth(
            principal=kerberos_principal,
            sanitize_mutual_error_response=False,
            force_preemptive=True
            )

    data = {
        "Mode": "newreq",
        "CertRequest": csr_content,
        "CertAttrib": f"CertificateTemplate:{template_name}",
    }

    response = requests.post(
        certsrv_url,
        auth=kerberos_auth,
        verify=ca_cert_path,
        data=data
    )
    print(response.status_code)

    os.remove(csr_path)

def generate_private_key_pem(file_path,uid,gid):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Serialize the private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(file_path, 'wb') as private_key_file:
        private_key_file.write(private_key_pem)
    os.chown(file_path, uid, gid)
    permissions = 0o400
    os.chmod(file_path, permissions)

    print(f"Private key written to: {file_path}")
    return private_key

def generate_csr(username, private_key, file_path):
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "TR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ""),
            x509.NameAttribute(NameOID.LOCALITY_NAME, ""),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ""),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ""),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])
    ).sign(private_key, hashes.SHA256(), default_backend())

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    with open(file_path, 'wb') as csr_file:
        csr_file.write(csr_pem)

    print(f"CSR written to: {file_path}")
    return csr
