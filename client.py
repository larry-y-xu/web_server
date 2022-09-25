import socket
import threading
import re
from datetime import datetime
import sys


mySocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
HOST_PORT = (sys.argv[1], int(sys.argv[2]))
mySocket.bind(("", 0))
FORMAT = "utf-8"
MAX_WIN = int(sys.argv[3])
PAYLOAD_LEN = int(sys.argv[4])

def main():
    #check and organize the number of files requested
    file_list = []
    out_list = [] 
    for i in range(5, len(sys.argv), 2):
        file_list.append(sys.argv[i])
        out_list.append(sys.argv[i + 1])
    sequence = 0
    ack = -1
    sequence, ack = handshake(sequence, ack, file_list)
    recv_loop(sequence, ack, file_list, out_list)
    #the teardown function is called within recv_loop
    
    
def handshake(sequence, ack, file_list):
    #check whether the connection should be persistent or not
    if len(file_list) > 1:
        http = "GET /" + file_list[0] + " HTTP/1.0\r\nConnection: keep-alive"
    else:
        http = "GET /" + file_list[0] + " HTTP/1.0\r\nConnection: close"
    send_length = len(http)
    msg = create_packet("SYN", sequence, send_length, ack, MAX_WIN, http)
    #while True:
    terminal_output("Send", "SYN", sequence, send_length, ack, MAX_WIN)
    mySocket.sendto(msg.encode(FORMAT), HOST_PORT)
        #cmd, r_sequence, r_length, r_ack, r_win, payload, lost_packet = receive_loss()
    cmd, r_sequence, r_length, r_ack, r_win, payload = receive_packet()
        #if not lost_packet:
            #break
    #mySocket.settimeout(None)
    
    #payload is an array
    ack = int(r_length) + 1
    terminal_output("Receive", "SYN|ACK", r_sequence, r_length, r_ack, MAX_WIN)
    sequence = int(send_length) + 1
        
    #send third part of 3 way handshake
    msg = create_packet("ACK", sequence, 0, ack, MAX_WIN, "")
    mySocket.sendto(msg.encode(FORMAT), HOST_PORT)
    terminal_output("Send", "ACK", sequence, 0, ack, MAX_WIN)

        
    #returns the current sequence number, and ack number
    return sequence, ack

def recv_loop(seq, ack, file_list, out_list):
    recv_buffer = MAX_WIN
    out_file = open(out_list[0], "w")
    while True:
        cmd, r_sequence, r_length, r_ack, r_win, payload= receive_packet()
        if cmd == "DAT":
            #server is requesting that the client send the name of the next file
            #remove files from the array so the program can detect whether or not there are more files
            file_list.pop(0)
            out_list.pop(0)
            out_file, seq, ack = send_next_file(file_list, out_list, seq, ack, recv_buffer)
            continue
        if cmd == "FIN|ACK":
            #server has transferred all files
            teardown(seq, ack, r_sequence, r_ack, r_win)
            break
            
        terminal_output("Receive", "DAT|ACK", r_sequence, r_length, r_ack, r_win)
        r_sequence = int(r_sequence)
        r_length = int(r_length)
        #in order packet, write to file
        #print(f"seq num of packet: {r_sequence} |||seq num expected:{ack}")
        if r_sequence == ack:
            ack += r_length
            recv_buffer -= r_length
            msg = create_packet("ACK", seq, 0, ack, recv_buffer, "")
            mySocket.sendto(msg.encode(FORMAT), HOST_PORT)
            terminal_output("Send", "ACK", seq, 0, ack, recv_buffer)
            out_file.write(payload[0])
            recv_buffer += r_length
        #not in order, send ack and let sender to deal with it
        else:
            msg = create_packet("ACK", seq, 0, ack, recv_buffer, "")
            mySocket.sendto(msg.encode(FORMAT), HOST_PORT)
            terminal_output("Send", "ACK", seq, 0, ack, recv_buffer)
 
            
    return

def send_next_file(file_list, out_list, seq, ack, buffer):
    #check whether the connection should be persistent or not
    if len(file_list) > 1:
        http = "GET /" + file_list[0] + " HTTP/1.0\r\nConnection: keep-alive"
    else:
        http = "GET /" + file_list[0] + " HTTP/1.0\r\nConnection: close"
    msg = create_packet("DAT", seq, len(http), ack, buffer, http)
    mySocket.sendto(msg.encode(FORMAT), HOST_PORT)
    terminal_output("Send", "DAT", seq, len(http), ack, buffer)
    out_file = open(out_list[0], "w")
    seq += len(http)
    return out_file, seq, ack

def teardown(seq, ack, r_seq, r_ack, r_win):
    #deallocate resources
    #server sending fin
    terminal_output("Receive", "FIN|ACK", r_seq, 0, r_ack, r_win)
    msg = create_packet("ACK", seq, 0, ack, MAX_WIN, "")
    mySocket.sendto(msg.encode(FORMAT), HOST_PORT)
    terminal_output("Send", "ACK", seq, 0, ack, MAX_WIN)
    
    #client sending fin
    seq += 1
    ack += 1
    msg = create_packet("FIN|ACK", seq, 0, ack, MAX_WIN, "")
    while True:
        mySocket.sendto(msg.encode(FORMAT), HOST_PORT)
        terminal_output("Send", "FIN|ACK", seq, 0, ack, MAX_WIN)
    #cmd, r_sequence, r_length, r_ack, r_win, payload = receive_packet()
        cmd, r_sequence, r_length, r_ack, r_win, payload, lost_packet = receive_loss()
        if not lost_packet:
            break
    terminal_output("Receive", "ACK", r_seq, 0, r_ack, r_win)


    
def create_packet(cmd, seq, length, ack, win, payload):
    return_str = f"{cmd}\r\nSequence: {seq}\r\nLength: {length}\r\nAcknowledgment: {ack}\r\nWindow: {win}\r\n\r\n{payload}"
    #print("_______SENDING________")
    #print(return_str)
    #print("________END___________\n")
    return return_str
    
def receive_packet():
    #try:
        #mySocket.settimeout(2)
    data, addr = mySocket.recvfrom(PAYLOAD_LEN * 2)
    #print("--------------RECEIVING----------------")
    #print(data.decode(FORMAT))
    #print("----------------END-------------------\n")
    cmd, seq, length, ack, win, payload = parse_packet(data.decode(FORMAT))
        #lost_packet = False
    #except socket.timeout:
        #lost_packet = True
        #cmd, payload = "", ""
        #seq,length, ack, win = 0, 0, 0, 0
        
    return cmd, seq, length, ack, win, payload

def receive_loss():
    try:
        mySocket.settimeout(2)
        data, addr = mySocket.recvfrom(PAYLOAD_LEN * 2)
        cmd, seq, length, ack, win, payload = parse_packet(data.decode(FORMAT))
        lost_packet = False
    except socket.timeout:
        lost_packet = True
        cmd = ""
        seq = 0
        length = 0
        ack = 0
        win = 0
        length = 0
        payload = ""
        
    return cmd, seq, length, ack, win, payload, lost_packet


def parse_packet(text):
    #returns payload as an array
    matchobj = re.match(r'(DAT\|ACK|SYN\|ACK|FIN\|ACK|DAT|ACK)\r\nSequence: (\d+)\r\nLength: (\d+)\r\nAcknowledgment: (\d+)\r\nWindow: (\d+)\r\n\r\n(.*)', text, flags=re.DOTALL)
    if matchobj.group(1) == "SYN|ACK":
        payload = re.split(r"\r\n", matchobj.group(6))
    elif matchobj.group(1) == "DAT|ACK":
        payload = [matchobj.group(6)]
    else:
        #fin
        payload = ""
    return matchobj.group(1), matchobj.group(2), matchobj.group(3), matchobj.group(4), matchobj.group(5), payload
    
        
        
def terminal_output(event, cmd, seq, length, ack, win):
    date = datetime.strftime(datetime.now().astimezone(), '%a %b %-d %H:%M:%S %Z %Y')
    print(f"{date}: {event}; {cmd}; Sequence: {seq}; Length: {length}; Acknowledgment: {ack}; Window: {win}")
    
    
if __name__ == "__main__":
    main()