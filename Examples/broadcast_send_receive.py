#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import time

########################################################################
# Broadcast Server class
########################################################################

class Sender:

    HOSTNAME = socket.gethostname()

    # Send the broadcast packet periodically. Set the period
    # (seconds).
    BROADCAST_PERIOD = 2

    # Define the message to broadcast.
    MSG_ENCODING = "utf-8"
    MESSAGE =  "Hello from " + HOSTNAME 
    MESSAGE_ENCODED = MESSAGE.encode('utf-8')

    # Use the broadcast-to-everyone IP address or a directed broadcast
    # address. Define a broadcast port.
    BROADCAST_ADDRESS = "255.255.255.255" # or 
    # BROADCAST_ADDRESS = "192.168.1.255"
    BROADCAST_PORT = 30000
    ADDRESS_PORT = (BROADCAST_ADDRESS, BROADCAST_PORT)

    def __init__(self):
        self.create_sender_socket()
        self.send_broadcasts_forever()

    def create_sender_socket(self):
        try:
            # Set up a UDP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            ############################################################
            # Set the option for broadcasting.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            ############################################################

            ############################################################
            # In more complex situations you may have to bind to an
            # interface.  This is to ensure that broadcasts are sent out
            # the correct interface, e.g.,
            # self.socket.bind(("192.168.1.22", 0))
            # self.socket.bind(("127.0.0.1", 0))
            ############################################################            
                
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def send_broadcasts_forever(self):
        try:
            while True:
                print("Sending to {} ...".format(Sender.ADDRESS_PORT))
                self.socket.sendto(Sender.MESSAGE_ENCODED, Sender.ADDRESS_PORT)
                time.sleep(Sender.BROADCAST_PERIOD)
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)

########################################################################
# Echo Receiver class
########################################################################

class Receiver:

    RECV_SIZE = 256

    HOST = "0.0.0.0"
    # HOST = "192.168.1.255"
    ADDRESS_PORT = (HOST, Sender.BROADCAST_PORT)

    def __init__(self):
        self.get_socket()
        self.receive_forever()

    def get_socket(self):
        try:
            # Create an IPv4 UDP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Bind to all interfaces and the agreed on broadcast port.
            self.socket.bind(Receiver.ADDRESS_PORT)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def receive_forever(self):
        while True:
            try:
                data, address = self.socket.recvfrom(Receiver.RECV_SIZE)
                print("Broadcast received: ", 
                      data.decode('utf-8'), address)
            except KeyboardInterrupt:
                print(); exit()
            except Exception as msg:
                print(msg)
                sys.exit(1)

########################################################################
# Process command line arguments if run directly.
########################################################################

if __name__ == '__main__':
    roles = {'receiver': Receiver,'sender': Sender}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='sender or receiver role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################






