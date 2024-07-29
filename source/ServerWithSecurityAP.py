import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback
from signal import signal, SIGINT
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


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
    address = args[1] if len(args) > 1 else "localhost"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(
                (address, port)
            )  # will listen to wtv address and port, if 0.0.0.0 it listens to all available network interfaces
            s.listen()

            client_socket, client_address = s.accept()
            with client_socket:
                while True:
                    match convert_bytes_to_int(read_bytes(client_socket, 8)):
                        case 0: # MODE 0
                            # If the packet is for transferring the filename
                            print("Receiving file...")
                            filename_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            filename = read_bytes(client_socket, filename_len).decode(
                                "utf-8"
                            )
                            # print(filename)
                        case 1: # MODE 1
                            # If the packet is for transferring a chunk of the file
                            start_time = time.time()

                            file_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            file_data = read_bytes(client_socket, file_len)
                            # print(file_data)

                            filename = "recv_" + filename.split("/")[-1]

                            # Write the file with 'recv_' prefix
                            with open(f"recv_files/{filename}", mode="wb") as fp:
                                fp.write(file_data)
                            print(
                                f"Finished receiving file in {(time.time() - start_time)}s!"
                            )
                        case 2: # MODE 2
                            # Close the connection
                            # Python context used here so no need to explicitly close the socket
                            print("Closing connection...")
                            s.close()
                            break
                        case 3:
                            """ Then the client expects to read FOUR messages from the server:
                            M1 from server: size of incoming M2 in bytes
                            M2 from server: signed authentication message
                            another M1 from server: size of incoming M2 in bytes (this is server_signed.crt)
                            another M2 from server: server_signed.crt """
                            print("Initiating Authentication Process")
                            auth_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            auth_msg = read_bytes(client_socket, auth_len)
                            with open("source/auth/server_private_key.pem", "rb") as key_file: # OBTAIN PRIVATE KEY TO SIGN THE AUTH MESSAGE
                                private_key = serialization.load_pem_private_key(
                                key_file.read(),
                                password=None,
                            )

                            signature = private_key.sign(
                                auth_msg,
                                padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH,
                                ),
                                hashes.SHA256(),  # Algorithm to hash the file_data before signing
                            )

                            client_socket.sendall(
                                convert_int_to_bytes(len(signature))
                            )  # send m1 = size of incoming M2 in bytes
                            client_socket.sendall(
                                signature
                            )  # send m2 = signed auth message

                            # now we send the server_signature.crt (which is the server's public key)

                            with open("source/auth/server_signed.crt", "rb") as key_file:
                                data = key_file.read()
                                client_socket.sendall(convert_int_to_bytes(len(data)))
                                client_socket.sendall(data)
                        case 4:
                            print("Received ping, sending pong...")
                            client_socket.sendall(
                                convert_int_to_bytes(len(convert_int_to_bytes(4)))
                            ) 
                            client_socket.sendall(convert_int_to_bytes(4)) 



    except Exception as e:
        print(e)
        s.close()


def handler(signal_received, frame):
    # Handle any cleanup here
    print("SIGINT or CTRL-C detected. Exiting gracefully")
    exit(0)


if __name__ == "__main__":
    # Tell Python to run the handler() function when SIGINT is recieved
    signal(SIGINT, handler)
    main(sys.argv[1:])
