#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import time

########################################################################
# You need to have EchoClientServer.py in the same directory!
########################################################################

# Use the standard echo client.
from EchoClientServer import Client

########################################################################
# Echo Server class
########################################################################

class Server:

    HOSTNAME = "0.0.0.0"
    PORT = 50000

    RECV_SIZE = 256
    BACKLOG = 10
    
    MSG_ENCODING = "utf-8"

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

            ############################################################
            # Set the (listen) socket to non-blocking mode.
            self.socket.setblocking(False)
            ############################################################            

            # Set socket to listen state.
            self.socket.listen(Server.BACKLOG)
            print("Listening on port {} ...".format(Server.PORT))
            
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def process_connections_forever(self):
        try:
            ############################################################
            # Keep a list of the current client connections.
            self.connected_clients = []
            ############################################################

            # The main loop that we execute forever.
            while True:
                self.check_for_new_connections()
                self.service_connected_clients()

                # Periodically output the current number of connections.
                print("{} ".format(len(self.connected_clients)), end="")
                sys.stdout.flush()
                time.sleep(0.1)

        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)
                
    def check_for_new_connections(self):                
        try:
            # Check if a new connection is available.
            new_client = self.socket.accept()
            new_connection, new_address_port = new_client

            # Announce that a new connection has been accepted.
            print("\nConnection received from {}.".format(new_address_port))

            # Set the new socket to non-blocking. 
            new_connection.setblocking(False)

            # Add the new connection to our connected_clients
            # list.
            self.connected_clients.append(new_client)
            
        except socket.error:
            # If an exception occurs, there are no new
            # connections. Continue on.
            pass

    def service_connected_clients(self):

        # Iterate through the list of connected clients, servicing
        # them one by one. Since we may delete from the list, make a
        # copy of it first.
        current_client_list = self.connected_clients.copy()

        for client in current_client_list:
            connection, address_port = client
            try:
                # Check for available incoming data.
                recvd_bytes = connection.recv(Server.RECV_SIZE)

                recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)
                # Check if the client has said "bye" or if the client
                # has closed the connection.
                if recvd_str == "bye" or len(recvd_str) == 0:
                    print()
                    print("Closing {} connection ...".format(address_port))
                    self.connected_clients.remove(client)
                    connection.close()
                    continue
                # Echo back what we received.
                connection.sendall(recvd_bytes)
                print("\nEcho: ", recvd_str)
            except socket.error:
                # If no bytes are available, catch the
                # exception. Continue on so that we can check
                # other connections.
                pass

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






