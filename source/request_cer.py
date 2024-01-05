'''
Author: Ali Rıza Girişen 
Date: 04/01/2024 
Email: <ali.girisen@pardus.org.tr>
'''
import requests,os,configparser
from requests_kerberos import HTTPKerberosAuth

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
    csr_file_path = config.get('KRB','csr_file_path')
    template_name = config.get('KRB','template_name')
    certsrv_url = config.get('KRB','certsrv_url')

    with open(csr_file_path, "r") as csr_file:
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
request_cer()
