import ipaddress
import logging
import os
from dataclasses import dataclass
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, pkcs12
from cryptography.x509.oid import NameOID


logging.basicConfig(level=logging.INFO)

BASE_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "ssl")

if not os.path.exists(BASE_DIR):
    logging.info(f"Create BASE_DIR: {BASE_DIR}")
    os.mkdir(BASE_DIR)


COUNTRY_NAME = "CH"
STATE_OR_PROVINCE_NAME = "Zurich"
LOCALITY_NAME = "Zurich"
ORGANIZATION_NAME = "MyOrg"


CA_DIR = os.path.join(BASE_DIR, "ca")
CA_CERT_PATH = os.path.join(CA_DIR, "cacert.pem")
CA_KEY_PATH = os.path.join(CA_DIR, "cakey.pem")

OPENSSL_CONF_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "openssl-ca.cnf"
)


@dataclass
class Broker:
    name: str
    keystorepass: str
    truststorepass: str
    ip_address: Optional[List[str]] = None
    dns: Optional[List[str]] = None
    export_jks: bool = True


brokers = [
    Broker(
        "kafka1",
        dns=["kafka1"],
        truststorepass="trustkafka1",
        keystorepass="keypw_kafka1",
    ),
    Broker(
        "kafka2",
        dns=["kafka2"],
        truststorepass="trustkafka2",
        keystorepass="keypw_kafka2",
    ),
    Broker(
        "kafka3",
        dns=["kafka3"],
        truststorepass="trustkafka3",
        keystorepass="keypw_kafka3",
    ),
    Broker(
        "zookeeper",
        dns=["zookeeper"],
        truststorepass="trustzookeeper",
        keystorepass="keypw_zookeeper",
    ),
    Broker(
        "zookeeper2",
        dns=["zookeeper2"],
        truststorepass="trustzookeeper2",
        keystorepass="keypw_zookeeper2",
    ),
    Broker(
        "zookeeper3",
        dns=["zookeeper3"],
        truststorepass="trustzookeeper3",
        keystorepass="keypw_zookeeper3",
    ),
    Broker(
        "kafkazookeeper",
        truststorepass="kafkazookeeper",
        keystorepass="kafkazookeeper",
    ),
    Broker(
        "zoonavigator",
        truststorepass="trust_zoonavigator",
        keystorepass="key_zoonavigator",
    ),
    Broker(
        "kafkaui",
        truststorepass="kafkauitrustpass",
        keystorepass="kafkauikeypass",
    ),
]


def create_ca(validity_days=3650):
    """Creates the CA"""
    logging.info("Creating CA")
    if not os.path.exists(CA_DIR):
        logging.info(f"Create CA_DIR: {CA_DIR}")
        os.mkdir(CA_DIR)

    os.chdir(CA_DIR)
    serial_path = os.path.join(CA_DIR, "serial.txt")
    if not os.path.exists(serial_path):
        with open(serial_path, "w") as f:
            f.write("01")

    index_path = os.path.join(CA_DIR, "index.txt")
    if not os.path.exists(index_path):
        with open(index_path, "w") as f:
            pass

    # Create CA
    if not os.path.exists(CA_CERT_PATH):
        logging.info("Creating CA:")
        command = f'openssl req -x509 -config {OPENSSL_CONF_PATH} -subj "/CN=CA" -newkey rsa:4096 -sha256 -nodes -days {validity_days} -keyout {CA_KEY_PATH} -out {CA_CERT_PATH} -outform PEM'
        os.system(command)
    else:
        logging.info("CA already exists.")


def create_broker(broker: Broker, validity_keystore_days=3650, validity_key_days=365):
    """Create keystore for broker"""

    logging.info(f"Create keys for broker {broker.name}")
    logging_prefix = f"Broker {broker.name}:"

    broker_dir = os.path.join(BASE_DIR, broker.name)

    if not os.path.exists(broker_dir):
        os.mkdir(broker_dir)

    os.chdir(broker_dir)

    private_key_path = os.path.join(broker_dir, "key.pem")
    csr_path = os.path.join(broker_dir, "csr.pem")
    signed_csr_path = os.path.join(broker_dir, "cert-signed.pem")
    keystore_path = os.path.join(broker_dir, f"{broker.name}.keystore.jks")
    truststore_path = os.path.join(broker_dir, f"{broker.name}.truststore.jks")
    cacert_path = os.path.join(broker_dir, "cacert.pem")

    # Generate key
    if not os.path.exists(private_key_path):
        logging.info(f"{logging_prefix} Generate new private key.")
        private_key: rsa.RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )

        with open(private_key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                    # encryption_algorithm=serialization.BestAvailableEncryption(
                    #     broker.keystorepass.encode()
                    # ),
                )
            )
    else:
        logging.info(f"{logging_prefix} Load existing key.")
        with open(private_key_path, "rb") as f:
            # key = load_pem_private_key(f.read(), password=broker.keystorepass.encode())
            key = load_pem_private_key(f.read(), password=None)

            if not isinstance(key, rsa.RSAPrivateKey):
                logging.error(f"{logging_prefix} not RSAPrivateKey, skipping")
                return
            private_key = key

    # Generate Certificate Signing Request (CSR)
    if not os.path.exists(signed_csr_path):
        logging.info(f"{logging_prefix} Generate Certificate Signing Request (CSR).")
        sans: List[x509.GeneralName] = []
        if broker.dns is not None:
            for dns in broker.dns:
                sans.append(x509.DNSName(dns))
        if broker.ip_address is not None:
            for ip_address in broker.ip_address:
                sans.append(x509.IPAddress(ipaddress.ip_address(ip_address)))

        common_name = broker.name
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        # Provide various details about who we are.
                        x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY_NAME),
                        x509.NameAttribute(
                            NameOID.STATE_OR_PROVINCE_NAME, STATE_OR_PROVINCE_NAME
                        ),
                        x509.NameAttribute(NameOID.LOCALITY_NAME, LOCALITY_NAME),
                        x509.NameAttribute(
                            NameOID.ORGANIZATION_NAME, ORGANIZATION_NAME
                        ),
                        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                    ]
                )
            )
            .add_extension(
                x509.SubjectAlternativeName(sans),
                critical=True,
            )
            # Sign the CSR with our private key.
            .sign(private_key, hashes.SHA256())
        )
        # Write our CSR out to disk.
        with open(csr_path, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

        logging.info(f"{logging_prefix} Sign Certificate Signing Request (CSR).")
        # Kafka Documentation: openssl ca -config openssl-ca.cnf -policy signing_policy -extensions signing_req -out {server certificate} -infiles {certificate signing request}
        # command = f"openssl ca -config {OPENSSL_CONF_PATH} -policy signing_policy -extensions signing_req -out {csr_path} -infiles {signed_csr_path}"
        # kafka-generate-ssl.sh: openssl x509 -req -CA $CA_CERT_FILE -CAkey $trust_store_private_key_file -in $KEYSTORE_SIGN_REQUEST -out $KEYSTORE_SIGNED_CERT -days $VALIDITY_IN_DAYS -CAcreateserial
        command = f"openssl x509 -req -CA {CA_CERT_PATH} -CAkey {CA_KEY_PATH} -in {csr_path} -out {signed_csr_path} -days {validity_key_days} -CAcreateserial"
        os.chdir(CA_DIR)
        os.system(command)
        os.chdir(broker_dir)
        os.remove(csr_path)

    if os.path.exists(signed_csr_path):
        with open(signed_csr_path, "rb") as f:
            signed_cert = x509.load_pem_x509_certificate(f.read())
    else:
        logging.error(
            f"{logging_prefix} Sign Certificate Signing Request does not exist. Skipping."
        )
        return

    # Load CA certificate
    if not os.path.exists(CA_CERT_PATH):
        logging.error(f"{logging_prefix} CA certificate does not exist. Skipping.")
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # Export JKS keystore
    if broker.export_jks:
        if not os.path.exists(keystore_path):
            logging.info(f"{logging_prefix} Export keystore")
            p12 = pkcs12.serialize_key_and_certificates(
                name=broker.name.encode(),
                key=private_key,
                cert=signed_cert,
                cas=[ca_cert],
                encryption_algorithm=serialization.BestAvailableEncryption(
                    broker.keystorepass.encode()
                ),
            )
            with open(keystore_path, "wb") as f:
                f.write(p12)

        # Export JKS truststore
        if not os.path.exists(truststore_path):
            logging.info(f"{logging_prefix} Export truststore")
            command = f'keytool -keystore {truststore_path} -alias CARoot -import -file {CA_CERT_PATH} -storepass "{broker.truststorepass}" -noprompt'
            os.system(command)
            # p12 = pkcs12.serialize_key_and_certificates(
            #     name=b"CARoot",
            #     key=None,
            #     cert=ca_cert,
            #     cas=[ca_cert],
            #     encryption_algorithm=serialization.BestAvailableEncryption(
            #         broker.truststorepass.encode()
            #     ),
            # )
            # with open(truststore_path, "wb") as f:
            #     f.write(p12)

    # Export CACert
    if not os.path.exists(cacert_path):
        with open(cacert_path, "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))


create_ca()

for broker in brokers:
    create_broker(broker)
