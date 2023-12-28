from ldap3 import Server, Connection, SUBTREE, ALL_ATTRIBUTES
import cryptography
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend

ad_server = 'win-l9up83kacsi.ornek.local'
ad_username = 'cn=Name Surname,cn=Users,dc=ornek,dc=local'
ad_password = "123456A."
base_dn = 'DC=ornek,DC=local'
user_to_query = 'namesurname'

server = Server(ad_server, get_info=ALL_ATTRIBUTES)
connection = Connection(server, user=ad_username, password=ad_password, auto_bind=True, receive_timeout=30, auto_referrals=False, raise_exceptions=True)

search_filter = f'(sAMAccountName={user_to_query})'
connection.search(base_dn, search_filter, SUBTREE, attributes=['userCertificate'])

# Parse and save the certificate as PEM file
for entry in connection.entries:
    for i, cert_data in enumerate(entry['userCertificate']):
        cert = load_der_x509_certificate(cert_data, default_backend())
        expiration_time = cert.not_valid_after

        pem_file_path = f"{user_to_query}_signed_certificate{i + 1}.pem"
        with open(pem_file_path, "wb") as pem_file:
            pem_file.write(cert.public_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM))

        print(f"Certificate Expiration Time: {expiration_time}")
        print(f"Certificate saved as PEM: {pem_file_path}")
        break

connection.unbind()
