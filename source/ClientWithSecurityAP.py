import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from threading import Thread, Event


def convert_int_to_bytes(x):
    """
    Convenience function to convert Python integers to a length-8 byte representation
    """
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    """
    Convenience function to convert byte value to integer value
    """
    return int.from_bytes(xbytes, "big")


def read_bytes(socket, length):
    """
    Reads the specified length of bytes from the given socket and returns a bytestring
    """
    buffer = []
    bytes_received = 0
    while bytes_received < length:
        data = socket.recv(min(length - bytes_received, 1024))
        if not data:
            raise Exception("Socket connection broken")
        buffer.append(data)
        bytes_received += len(data)

    return b"".join(buffer)


def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"
    print("port:", port)
    print("server address:", server_address)

    start_time = time.time()

    # try:
    print("Establishing connection to server...")
    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected, sending Auth Messages")

        # this method is used to ping the server, to check that server is up during long term processes.
        # We will essentially send pings every 5 seconds to server and expect an answer. this is done in another thread so it
        # doesnt block the main processes
        def send_ping(stop_event):
            while not stop_event.is_set():
                try:
                    s.sendall(convert_int_to_bytes(4))  # mode 4
                    print("sent ping")
                    pong_len = convert_bytes_to_int(read_bytes(s, 8))
                    pong = convert_bytes_to_int(read_bytes(s, pong_len))

                    print(pong)
                    if pong != 4:
                        raise Exception("Did not receive expected pong message.")
                    print("Received pong from server.")
                except Exception as e:
                    print(f"Server failed to respond: {e}")
                    s.sendall(convert_int_to_bytes(2))  # Close the connection
                    s.close()
                    sys.exit(1)
                stop_event.wait(5)  # wait for 5 seconds before the next ping

        stop_event = Event()
        ping_thread = Thread(target=send_ping, args=(stop_event,))
        ping_thread.start()
        # Send Mode=3, M1, M2, to the Server after connected

        s.sendall(convert_int_to_bytes(3))  # send mode = 3
        s.sendall(
            convert_int_to_bytes(len(b"Client Request"))
        )  # send m1 = size of incoming M2 in bytes
        s.sendall(b"Client Request")  # send m2 = signed authentication message

        # afterwhich we get reply from server
        try:
            while True:
                signed_auth_len = convert_bytes_to_int(read_bytes(s, 8))
                signed_auth = read_bytes(s, signed_auth_len)
                print(f"Received Signed Auth Msg From server!")

                server_signed_len = convert_bytes_to_int(read_bytes(s, 8))
                server_signed = read_bytes(s, server_signed_len)
                print(f"Received signed server public key")
                with open("source/auth/cacsertificate.crt", "rb") as f:
                    ca_cert = x509.load_pem_x509_certificate(
                        f.read(), default_backend()
                    )

                server_cert = x509.load_pem_x509_certificate(
                    server_signed, default_backend()
                )

                ca_public_key = ca_cert.public_key()

                try:
                    ca_public_key.verify(
                        server_cert.signature,
                        server_cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        server_cert.signature_hash_algorithm,
                    )
                    print(
                        "The server certificate is verified and has been signed by the CA."
                    )
                except InvalidSignature:
                    print(
                        "The server certificate is not verified or has not been signed by the CA."
                    )
                    s.sendall(convert_int_to_bytes(2))  # Close the connection
                    s.close()
                    return
                server_public_key = server_cert.public_key()
                try:
                    server_public_key.verify(
                        signed_auth,
                        b"Client Request",
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA256(),
                    )
                    print("The signature is valid.")
                except InvalidSignature:
                    print("The signature is invalid.")
                    s.sendall(convert_int_to_bytes(2))  # Close the connection
                    s.close()
                    return

                break  # Exit after receiving the expected messages
        except Exception as e:
            print(f"Error while reading from server: {e}")
            s.sendall(convert_int_to_bytes(2))  # Close the connection
            s.close()
            return

        # now we have verified the public key, lets try to ensure that signed_auth is verified first

        while True:

            filename = input("Enter a filename to send (enter -1 to exit):").strip()

            while filename != "-1" and (not pathlib.Path(filename).is_file()):
                filename = input("Invalid filename. Please try again:").strip()

            if filename == "-1":
                s.sendall(convert_int_to_bytes(2))  # MODE 2, close connection
                break

            filename_bytes = bytes(filename, encoding="utf8")

            # Send the filename
            s.sendall(convert_int_to_bytes(0))  # mode 0
            s.sendall(convert_int_to_bytes(len(filename_bytes)))  # m1 = len of m2
            s.sendall(filename_bytes)  # m2 = filename bytes

            # Send the file
            with open(filename, mode="rb") as fp:
                data = fp.read()
                s.sendall(convert_int_to_bytes(1))
                s.sendall(convert_int_to_bytes(len(data)))
                s.sendall(data)

        # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])
