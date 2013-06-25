#basic python UDP script
#for testing only
import socket

UDP_IP = "127.0.0.1"
UDP_PORT = 5004

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

#send ping request to our DHT on localhost.
sock.sendto("0012345678".decode("hex") + "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH", ('127.0.0.1', 33445))

#print all packets recieved and respond to ping requests properly
while True:
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    print "received message:", data, " From:", addr
    sock.sendto("01".decode('hex') + data[1:5] + "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH", addr)
