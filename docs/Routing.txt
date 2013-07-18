Routing Protocol.

The routing protocol will only be used when two clients have difficulty 
connecting to each other. This is usually because of NAT issues. For example, 
two people who are behind symmetric NATs are not capable of connecting to each 
other directly.

The routing protocol severely limits the speed at which two clients can 
communicate. This is so that the user of the software does not feel the need to 
turn it off because it is taking too much bandwidth and to prevent peers from 
using it without good reason.

The routing protocol does not provide any anonymity, only convenience.

#############

Draft of protocol:

Alice wants to connect to Bob.

Alice queries the DHT and manages to obtain the ip_port of Bob from Carol and 
Dan both of who are closest mathematically to Bob in the DHT.

Unfortunately Alice is enable to connect to the ip_port for Bob provided by 
Carol and Dan.

Alice assumes then that Bob is behind a bad NAT.

Alice therefore randomly picks between Carol and Dan. She picks Carol.

Alice connects to Carol using the Lossless UDP protocol.

She then sends a routing request over the connection:

[char with a value of 16][Public key of who to route the packets to(client_id) 
(32 bytes)]

Carol checks if she is connected via the DHT to the person (Bob) who the public 
key appears in the routing request.

If she is not she kills the connection.

If she is, she waits for the next data packet to arrive from Alice.

As soon as she receives it she connects to the person (Bob) and sends it to him.

If nothing is received from Bob within a timeout, the connection is killed.

If something is received from Bob, it is sent to Alice and the connection is 
confirmed and continues until either Bob or Alice disconnect.

#############

Some notes:

If both Alice and Bob are friends they will create two different connections 
when each try to connect to each other witch is good because it means data can 
be sent/received on both which lower the chances of the connection being 
severed because the node shut itself down or data being lost because of a bad 
node. It however doubles the amount of data we send/receive.

If both peers manage to connect to each other, the routing connection is 
killed.

All data transmitted trough this protocol must be encrypted in a way that it is 
only decryptable by the receiver and only the receiver.
