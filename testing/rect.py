#basic python UDP script
#for testing only
import socket
import random

UDP_IP = "127.0.0.1"
UDP_PORT = 5004

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

#our client_id
client_id = str(''.join(random.choice("abcdefghijklmnopqrstuvwxyz") for x in range(32)))

print client_id
a = 1;
#send ping request to our DHT on localhost.
sock.sendto("0012345678".decode("hex") + client_id, ('127.0.0.1', 33445))

#print all packets recieved and respond to ping requests properly
while True:
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    print "received message:", data.encode('hex'), " From:", addr
    #if we recieve a ping request.
    print data[0].encode('hex')
    if data[0] == "00".decode('hex'):
        print "Sending ping resp"
        sock.sendto("01".decode('hex') + data[1:5] + client_id, addr)
        
    #if we recieve a get_nodes request.
    if data[0] == "02".decode('hex'):
        print "Sending getn resp"
        #send send nodes packet with a couple 127.0.0.1 ips and ports.
        #127.0.0.1:5000, 127.0.0.1:5001, 127.0.0.1:5002
        sock.sendto("03".decode('hex') + data[1:5] + client_id + ("HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH" + "7F00000113880000".decode('hex') + "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH" + "7F00000113890000".decode('hex') + "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH" + "7F000001138A0000".decode('hex')), addr)
    
    if data[0] == "10".decode('hex'):
        print "Sending handshake resp"
        sock.sendto("10".decode('hex') + data[1:5] + client_id[:4], addr)
    if data[0] == "11".decode('hex'):
        print "Sending SYNC resp"
        a+=1
        sock.sendto("11".decode('hex') + chr(a) + data[1:9], addr)
        
