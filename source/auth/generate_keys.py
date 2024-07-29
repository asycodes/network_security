from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import sys

""" this file basically generates the private key and the cert signing request, signing the csr
with the private key. CSR is used by the CA (which is verisign or wtv) to generate the cert,
where we can get the public key

Steps:
1. Generate a private key.
2. Write the private key to a file for safe keeping.
3. Create a CSR with the generated private key and necessary details.
4. Write the CSR to a file.
5. Send this to the CA to get it signed and get the CRT file which contains public key of server
6. The cacsertificate.crt can be used to verify that this is indeed the signed by the CA, this process can be initiliased by client
, this crt contains CA's public key.
hence self signed cert because csertificate( our pretending CA) is not an official CA. Theres no actual trust factor.

The CSR can then be used by a CA to issue a certificate. """

if len(sys.argv) == 1:
    suffix = ""
else:
    suffix = sys.argv[1]

# Generate our key
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024,
)

# Write our private key to disk for safe keeping
with open(suffix + "_private_key.pem", "wb") as f:
    f.write(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

# Generate a CSR (certificate signing request)
csr = (
    x509.CertificateSigningRequestBuilder()
    .subject_name(
        x509.Name(
            [
                # Provide various details about who we are.
                x509.NameAttribute(NameOID.COUNTRY_NAME, "SG"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Singapore"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Singapore"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SUTD"),
                x509.NameAttribute(NameOID.COMMON_NAME, "sutd.edu.sg"),
            ]
        )
        # Sign the CSR with our private key.
    )
    .sign(key, hashes.SHA256())
)

# Write our CSR out to disk.
with open(suffix + "_certificate_request.csr", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))
