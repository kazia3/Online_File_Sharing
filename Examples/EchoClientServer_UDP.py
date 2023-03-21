#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import time

########################################################################
# Echo Server class
########################################################################

class Server:

    HOSTNAME = "0.0.0.0" # socket.gethostname()
    PORT = 50000

    RECV_SIZE = 256
    BACKLOG = 10
    
    MSG_ENCODING = "utf-8"

    def __init__(self):
        self.create_listen_socket()
        self.process_messages_forever()

    def create_listen_socket(self):
        try:
            # Create an IPv4 UDP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Set socket layer socket options.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and
            # port. Unlike TCP, there is no listen/accept. We can just
            # receive on the bound port.
            self.socket.bind( (Server.HOSTNAME, Server.PORT) )
            print("Listening on port {} ...".format(Server.PORT))

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def process_messages_forever(self):
        try:
            while True:
                # Do a recvfrom in order to obtain the identity of the
                # sender of the incoming packet.
                self.message_handler(self.socket.recvfrom(Server.RECV_SIZE))

        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            print("Closing server socket ... ")
            self.socket.close()
            sys.exit(1)

    def message_handler(self, client):
        # recvfrom returns the contents of the received segment and
        # the identity of the sender.
        msg_bytes, address_port = client
        msg = msg_bytes.decode(Server.MSG_ENCODING)
        print("-" * 72)
        print("Message received from {}.".format(address_port))
        # print("Received Message Bytes: ", msg_bytes)
        # print("Decoded Message: ", msg)
        # time.sleep(20) # for attacker.

        # Echo the received bytes back to the sender.
        self.socket.sendto(msg_bytes, address_port)
        print("Echoed Message: ", msg)
        # print("Encoded Echoed Message Bytes: ", msg_bytes)

########################################################################
# Echo Client class
########################################################################

class Client:

    SERVER_ADDRESS_PORT = ('localhost', Server.PORT)
    RECV_SIZE = 256

    def __init__(self):
        self.get_socket()
        self.send_console_input_forever()

    def get_socket(self):
        try:
            # Create an IPv4 UDP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Set socket layer socket options.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_console_input(self):
        # In this version we keep prompting the user until a non-blank
        # line is entered.
        while True:
            self.input_text = input("Input: ")
            if self.input_text != '':
                 self.input_text_encoded = self.input_text.encode(Server.MSG_ENCODING)
                 break
    
    def send_console_input_forever(self):
        while True:
            try:
                self.get_console_input()
                self.message_send()
                self.message_receive()
            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing client socket ...")
                self.socket.close()
                sys.exit(1)
                
    def message_send(self):
        try:
            # sendto takes the bytes to be sent and the identity of
            # the destination.
            self.socket.sendto(self.input_text_encoded, Client.SERVER_ADDRESS_PORT)
            # print("Sent Message: ", self.input_text)
            # print("Sent Message Bytes: ", self.input_text_encoded)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def message_receive(self):
        try:
            # recvfrom returns bytes received and the identity of the
            # sender.
            recvd_bytes, address = self.socket.recvfrom(Client.RECV_SIZE)
            # print("Received Message Bytes: ", recvd_bytes)
            print("Received Message: ", recvd_bytes.decode(Server.MSG_ENCODING))
        except Exception as msg:
            print(msg)
            sys.exit(1)

########################################################################
# Process command line arguments if run directly.
########################################################################

if __name__ == '__main__':
    roles = {'client': Client,'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################






