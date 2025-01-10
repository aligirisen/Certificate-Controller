import configparser, os
import ssl
import socket
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from .logger_utils import get_logger
logger = get_logger(__name__)

def update_client_ca(server_uri, output_path):

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    logger.info("Client CA updated...")

    with socket.create_connection((server_uri, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=server_uri) as ssock:
            cert_data = ssock.getpeercert(True)
            cert = x509.load_der_x509_certificate(cert_data, default_backend())

    with open(output_path, 'wb') as cert_file:
        cert_file.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

    subprocess.run(['sudo', 'update-ca-certificates'])

