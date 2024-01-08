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
from cryptography.x509.oid import NameOID

def request_cer():
    config_path = "/etc/certificate_controller/config.ini"
    if os.path.exists(config_path):
        pass
    else:
        config_path = "config/config.ini"

    config = configparser.ConfigParser()
    config.read(config_path)
    kerberos_principal = config.get('KRB','kerberos_principal')
    kerberos_keytab = config.get('KRB','kerberos_keytab')
    ca_cert_path = config.get('KRB','ca_cert_path')
    template_name = config.get('KRB','template_name')
    certsrv_url = config.get('KRB','certsrv_url')

    username = os.environ.get('SUDO_USER')
    if username is None:
        print("Certificate-Controller need sudo privileges")
        return 0
    sensitive_keys = f"/home/{username}/.certificate_controller/"
    private_key_path = f'{sensitive_keys}private_key.pem'
    csr_path = f'{sensitive_keys}csr.csr'

    if os.path.exists(csr_path):
        with open(csr_path, "r") as csr_file:
            csr_content = csr_file.read()
    else:
        os.mkdir(sensitive_keys)
        private_key = generate_private_key_pem(private_key_path)
        generate_csr(private_key, csr_path)
        with open(csr_path, "r") as csr_file:
            csr_content = csr_file.read()

    # Kerberos authentication using keytab
    kerberos_auth = HTTPKerberosAuth(principal=kerberos_principal, sanitize_mutual_error_response=False, force_preemptive=True)

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

def generate_private_key_pem(file_path):
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

    print(f"Private key written to: {file_path}")
    return private_key

def generate_csr(private_key, file_path):
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
