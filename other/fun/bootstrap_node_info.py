#!/usr/bin/env python
"""
Copyright (c) 2014 by nurupo <nurupo.contributions@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

from socket import *
import sys

if sys.version_info[0] == 2:
    print("This script requires Python 3+ in order to run.")
    sys.exit(1)

def printHelp():
    print("Usage: " + sys.argv[0] + " <ipv4|ipv6> <ip/hostname> <port>")
    print("  Example: " + sys.argv[0] + " ipv4 192.210.149.121 33445")
    print("  Example: " + sys.argv[0] + " ipv4 23.226.230.47 33445")
    print("  Example: " + sys.argv[0] + " ipv4 biribiri.org 33445")
    print("  Example: " + sys.argv[0] + " ipv4 cerberus.zodiaclabs.org 33445")
    print("  Example: " + sys.argv[0] + " ipv6 2604:180:1::3ded:b280 33445")
    print("")
    print("Return values:")
    print("  0 - received info reply from a node")
    print("  1 - incorrect command line arguments")
    print("  2 - didn't receive any reply from a node")
    print("  3 - received a malformed/unexpected reply")

if len(sys.argv) != 4:
    printHelp()
    sys.exit(1)

protocol = sys.argv[1]
ip = sys.argv[2]
port = int(sys.argv[3])

INFO_PACKET_ID = b"\xF0"         # https://github.com/irungentoo/toxcore/blob/4940c4c62b6014d1f0586aa6aca7bf6e4ecfcf29/toxcore/network.h#L128
INFO_REQUEST_PACKET_LENGTH = 78  # https://github.com/irungentoo/toxcore/blob/881b2d900d1998981fb6b9938ec66012d049635f/other/bootstrap_node_packets.c#L28
# first byte is INFO_REQUEST_ID, other bytes don't matter as long as reqest's length matches INFO_REQUEST_LENGTH
INFO_REQUEST_PACKET = INFO_PACKET_ID + ( b"0" * (INFO_REQUEST_PACKET_LENGTH - len(INFO_PACKET_ID)) )

PACKET_ID_LENGTH = len(INFO_PACKET_ID)
VERSION_LENGTH = 4    # https://github.com/irungentoo/toxcore/blob/881b2d900d1998981fb6b9938ec66012d049635f/other/bootstrap_node_packets.c#L44
MAX_MOTD_LENGTH = 256 # https://github.com/irungentoo/toxcore/blob/881b2d900d1998981fb6b9938ec66012d049635f/other/bootstrap_node_packets.c#L26

MAX_INFO_RESPONSE_PACKET_LENGTH = PACKET_ID_LENGTH + VERSION_LENGTH + MAX_MOTD_LENGTH

SOCK_TIMEOUT_SECONDS = 1.0

sock = None

if protocol == "ipv4":
    sock = socket(AF_INET, SOCK_DGRAM)
elif protocol == "ipv6":
    sock = socket(AF_INET6, SOCK_DGRAM)
else:
    print("Invalid first argument")
    printHelp()
    sys.exit(1)

sock.sendto(INFO_REQUEST_PACKET, (ip, port))

sock.settimeout(SOCK_TIMEOUT_SECONDS)

try:
   data, addr = sock.recvfrom(MAX_INFO_RESPONSE_PACKET_LENGTH)
except timeout:
   print("The DHT bootstrap node didn't reply in " + str(SOCK_TIMEOUT_SECONDS) + " sec.")
   print("The likely reason for that is that the DHT bootstrap node is either offline or has no info set.")
   sys.exit(2)

packetId = data[:PACKET_ID_LENGTH]
if packetId != INFO_PACKET_ID:
    print("Bad response, first byte should be", INFO_PACKET_ID, "but got", packetId, "(", data, ")")
    print("Are you sure that you are pointing the script at a Tox DHT bootstrap node and that the script is up to date?")
    sys.exit(3)

version = int.from_bytes(data[PACKET_ID_LENGTH:PACKET_ID_LENGTH + VERSION_LENGTH], byteorder='big')
motd = data[PACKET_ID_LENGTH + VERSION_LENGTH:].decode("utf-8")
print("Version: " + str(version))
print("MOTD:    " + motd)
sys.exit(0)