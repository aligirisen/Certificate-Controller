import requests
from requests_kerberos import HTTPKerberosAuth

# Replace these with your actual values
kerberos_principal = "user1@ORNEK.LOCAL"
kerberos_keytab = "/etc/krb5.keytab"
ca_cert_path = "/etc/ssl/certs/ca-certificates.crt"
csr_file_path = "csr.csr"
template_name = "User"
certsrv_url = "http://win-l9up83kacsi.ornek.local/certsrv/certfnsh.asp"

# Read the CSR file content
with open(csr_file_path, "r") as csr_file:
    csr_content = csr_file.read()

# Kerberos authentication using keytab
kerberos_auth = HTTPKerberosAuth(principal=kerberos_principal, sanitize_mutual_error_response=False, force_preemptive=True)

# Data to be sent in the request
data = {
    "Mode": "newreq",
    "CertRequest": csr_content,
    "CertAttrib": f"CertificateTemplate:{template_name}",
}

# Send the HTTP request
response = requests.post(
    certsrv_url,
    auth=kerberos_auth,
    verify=ca_cert_path,
    data=data
)
print(response.status_code)
