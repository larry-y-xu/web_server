Starting with UDP as a base, implements some of the features present 
in TCP: flow control, error control for best effort packet delivery
even with network delay and loss.

Flow control is achieved through packet header sequence and 
acknowledgement numbers, while error control is implemented
through Go-Back-N, using a sliding window advertised by the 
receiver.

The session is initiated and ended in much the same way as
TCP, with a 3 way handshake for setup and 4 way handshake
for teardown.
