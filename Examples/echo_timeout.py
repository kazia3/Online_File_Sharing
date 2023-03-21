#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import time

from EchoClientServer import Client

########################################################################
# Echo-Server class
########################################################################

########################################################################
# A basic echo server that illustrates how to set a time-out on socket
# accepts and recvs. See the commented statements below.
########################################################################

class Server:

    HOSTNAME = "0.0.0.0"
    PORT = 50000

    RECV_SIZE = 1024
    BACKLOG = 10
    
    MSG_ENCODING = "utf-8"

    ACCEPT_TIMEOUT = 1
    RECV_TIMEOUT = 1

    def __init__(self):
        self.create_listen_socket()
        self.process_connections_forever()

    def create_listen_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Get socket layer socket options.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.socket.bind( (Server.HOSTNAME, Server.PORT) )

            # Set socket to listen state.
            self.socket.listen(Server.BACKLOG)
            print("Listening on port {} ...".format(Server.PORT))

            ############################################################
            # Set the listen socket timeout.
            self.socket.settimeout(Server.ACCEPT_TIMEOUT);
            ############################################################

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def process_connections_forever(self):
        try:
            while True:
                # Accept an echo client connection.  When one is
                # accepted, pass the new socket reference to the
                # connection handler. 

                ########################################################
                # Use a try/except block to capture the the accept
                # timeout. The while True block will try the accept
                # again.
                ########################################################
                try:
                    client = self.socket.accept()
                    self.connection_handler(client)
                except socket.timeout:
                    print("Socket accept timeout ...")
                ########################################################
                # End of try/except block
                ########################################################

        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)

    def connection_handler(self, client):
        connection, address_port = client
        print("-" * 72)
        print("Connection received from {}.".format(address_port))

        ################################################################
        # Set the recv timeout for the new socket.
        connection.settimeout(Server.RECV_TIMEOUT);
        ################################################################

        while True:
            ########################################################
            # Beginning of try/except block to capture a recv
            # timeout. The while True block will try the recv again.
            ########################################################
            try:
                recvd_bytes = connection.recv(Server.RECV_SIZE)
            
                # If recv returns with zero bytes, the other end of the
                # TCP connection has closed (The other end is probably in
                # FIN WAIT 2 and we are in CLOSE WAIT.). If so, close the
                # server end of the connection and get the next client
                # connection.
                if len(recvd_bytes) == 0:
                    print("Closing client connection ... ")
                    connection.close()
                    break
                    
                # Decode the received bytes back into strings. Then output
                # them.
                recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)
                print("Received: ", recvd_str)
                    
                # Send the received bytes back to the client.
                connection.sendall(recvd_bytes)
                print("Sent: ", recvd_str)
            except socket.timeout:
                    print("Socket recv timeout ...")
                    pass
            ############################################################
            # End of try/except block
            ############################################################

            except KeyboardInterrupt:
                print()
                print("Closing client connection ... ")
                connection.close()
                break

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






