import socket
import threading
import re
from datetime import datetime
import sys


mySocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
HOST_PORT = (sys.argv[1], int(sys.argv[2]))
mySocket.bind(HOST_PORT)
FORMAT = "utf-8"
MAX_WIN = int(sys.argv[3])
PAYLOAD_LEN = int(sys.argv[4])

def main():
    while True:
        data, address = mySocket.recvfrom(MAX_WIN * 2)
        client_handler(data, address)
        
def client_handler(dat, addr):
    valid, file_pointer, seq, ack, client_window, persistent, dupe = handshake(dat, addr)
    if dupe:
        msg = packet("ACK", seq, 0, ack, MAX_WIN, "")
        mySocket.sendto(msg.encode(FORMAT), addr)
        mySocket.settimeout(None)
        return
    
    while True:
        if not valid and not persistent:
            #end condition when the last file is invalid
            break
    
        if not valid:
            #not valid, but still persistent
            #move onto next file
            while True:
                msg = packet("DAT", seq, 0 , ack, MAX_WIN, "")
                mySocket.sendto(msg.encode(FORMAT), addr)
                cmd, recv_seq, recv_length, recv_ack, recv_win, payload, lost_packet = receive_packet()
                if not lost_packet:
                    break
            file_pointer, valid, persistent, http_payload, http = next_file(payload, addr)
            continue
        
        #here we know the file is valid, and we should send it to the client
        #create packets
        file_store, num_pck, last_seq = read_file(file_pointer, seq, ack)
        #send packets
        seq, ack = send_loop(file_store, seq, ack, int(client_window), addr, persistent, last_seq)
        if persistent:
            #next file
            while True:
                msg = packet("DAT", seq, 0 , ack, MAX_WIN, "")
                mySocket.sendto(msg.encode(FORMAT), addr)
                cmd, recv_seq, recv_length, recv_ack, recv_win, payload, lost_packet = receive_packet()
                if not lost_packet:
                    break
            file_pointer, valid, persistent, http_payload, http = next_file(payload, addr)
        else:
            #we have finished sending a file(s), and we know there are no more files to read
            #end condition when the last file is valid
            break           
        
    teardown(seq, ack, addr)
    
def handshake(data, address):
    #performs the tcp 3 way handshake
    cmd, c_sequence, length, c_ack, win, payload = parse(data.decode(FORMAT))
    duplicate = False
    if cmd == "FIN|ACK":
        duplicate = True
        valid_file, file_pointer, seq, ack, win, persistent = 0, 0, 0, 0, 0, 0
        return valid_file, file_pointer, seq, ack, win, persistent, duplicate
    file_pointer, valid_file, persistent, http_payload, http = next_file(payload, address)
    seq = 0
    ack = int(length) + 1
    #temp_seq = len(http_payload) + 1
    sending_length = len(http_payload)
    msg = packet("SYN|ACK", seq, sending_length, ack, MAX_WIN, http_payload)
    #terminal_output(address[0], address[1], payload[0], http)
    while True:
        mySocket.sendto(msg.encode(FORMAT), address)
        seq = len(http_payload) + 1
        #recv third part of handshake
        cmd, recv_seq, recv_length, recv_ack, recv_win, payload, lost_packet = receive_packet()
        if not lost_packet:
            break
    return valid_file, file_pointer, seq, ack, win, persistent, duplicate

def read_file(file_pointer, temp_seq, ack):
    file_store = {}
    num_pck = 0
    while True:
        bytes_read = file_pointer.read(PAYLOAD_LEN)
        if not bytes_read:
            break
        bytes_read = bytes_read.decode(FORMAT)
        file_store[temp_seq] = packet("DAT|ACK", temp_seq, len(bytes_read), ack, MAX_WIN, bytes_read)
        #file_store[temp_seq] = packet
        temp_seq += len(bytes_read)
        num_pck += 1
    
    return file_store, num_pck, temp_seq
    
    
def send_loop(file_store, seq, ack, client_win, address, persistent, last_seq):
    confirmed_ack = seq
    lost_packet = False
    available_buffer = client_win #buffer space
    #while we have not received the ack for the last packet
    while confirmed_ack < last_seq:
        #continue sending
        while available_buffer > 0 and seq < last_seq: #sent < num_pck:
            current_packet = file_store.get(seq)
            current_length = int(get_len(current_packet))
            mySocket.sendto(current_packet.encode(FORMAT), address)
            available_buffer -= current_length
            seq += current_length
                
                
        #wait for acks
        while True:#sent_and_ack != sent_not_ack:
            cmd, recv_seq, recv_length, recv_ack, recv_win, payload, lost_packet = receive_packet()
            #assuming received packets are in order
            if int(recv_ack) > seq:
                #ack was lost
                seq = int(recv_ack)
                #print(f"Changing confirmed ack from: {confirmed_ack}|to: {int(recv_ack)}")
                confirmed_ack = int(recv_ack)
                available_buffer = int(recv_win)
                lost_packet = False
                break
                
            #no packet lost
            if not lost_packet:
                available_buffer = int(recv_win)
                #print(f"changing confirmed ack from: {confirmed_ack}|to: {int(recv_ack)}")
                confirmed_ack = int(recv_ack)
                if int(recv_ack) == seq:
                    #all packets sent and received
                    break
            
            #assumed packet loss
            else:
                #we never received the ack for this packet, so we resend it
                seq = confirmed_ack
                available_buffer = client_win
                break
                
    #next file, or terminate if non persistent
    return seq, ack

def next_file(payload, address):
    #takes the payload, checks whether there is a 404
    #checks whether the connection is persistent
    #returns these values along with the file_pointer
    matchtwo = re.match(r"Connection: (.*)", payload[1]) 
    if matchtwo.group(1) == "keep-alive":
        http_two = "\r\nConnection: keep-alive"
        persistent = True
    else:
        http_two = "\r\nConnection: close"
        persistent = False
        
    matchobj = re.match(r"GET /(.*) HTTP/1.0", payload[0])
    file = matchobj.group(1)
    
    #open file
    file_pointer = 0 #to keep compiler happy
    try:
        file_pointer = open(file, "rb")
        valid_file = True
    except:
        valid_file = False
    
    if valid_file == False:
        http = "HTTP/1.0 404 NOT FOUND"
    else:
        http = "HTTP/1.0 200 OK"
    http_payload = http + http_two
    terminal_output(address[0], address[1], payload[0], http)
    
    return file_pointer, valid_file, persistent, http_payload, http

def teardown(seq, ack, address):
    #deallocate resources
    #server sends fin
    msg = packet("FIN|ACK", seq, 0, ack, MAX_WIN, "")
    while True:
        mySocket.sendto(msg.encode(FORMAT), address)
        cmd, recv_seq, recv_length, recv_ack, recv_win, payload, lost_packet = receive_packet()
        if not lost_packet:
            break
        
    #client sends fin
    cmd, recv_seq, recv_length, recv_ack, recv_win, payload = receive_wait()
    seq += 1
    ack += 1
    msg = packet("ACK", seq, 0, ack, MAX_WIN, "")
    mySocket.sendto(msg.encode(FORMAT), address)
    mySocket.settimeout(None)
    return


        
def parse(text):
    matchobj = re.match(r'(SYN|ACK|FIN\|ACK|DAT)\r\nSequence: (\d+)\r\nLength: (\d+)\r\nAcknowledgment: (.\d+)\r\nWindow: (\d+)\r\n\r\n(.*)', text, flags=re.DOTALL)
    if matchobj.group(1) == "SYN" or matchobj.group(1) == "DAT":
        payload = re.split(r"\r\n", matchobj.group(6))
    elif matchobj.group(1) == "ACK":
        payload = ""
    else:
        payload = ""
    return matchobj.group(1), matchobj.group(2), matchobj.group(3), matchobj.group(4), matchobj.group(5), payload

    
def packet(cmd, seq, length, ack, win, payload):
    return_str = f"{cmd}\r\nSequence: {seq}\r\nLength: {length}\r\nAcknowledgment: {ack}\r\nWindow: {win}\r\n\r\n{payload}"
    return return_str

def get_len(text):
    matchobj = re.match(r'(DAT\|ACK)\r\nSequence: (\d+)\r\nLength: (\d+)\r\nAcknowledgment: (\d+)\r\nWindow: (\d+)\r\n\r\n(.*)', text, flags=re.DOTALL)
    if not matchobj:
        print(text)
    return matchobj.group(3)

def receive_wait():
    data, addr = mySocket.recvfrom(PAYLOAD_LEN * 2)
    cmd, seq, length, ack, win, payload = parse(data.decode(FORMAT))
    return cmd, seq, length, ack, win, payload

def receive_packet():
    try:
        mySocket.settimeout(2)
        data, addr = mySocket.recvfrom(PAYLOAD_LEN * 2)
        cmd, seq, length, ack, win, payload = parse(data.decode(FORMAT))
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
        

    
def terminal_output(c_ip, c_port, request, response):
    date = datetime.strftime(datetime.now().astimezone(), '%a %b %-d %H:%M:%S %Z %Y')
    print(f"{date}: {c_ip}:{c_port} {request}; {response}")
    
if __name__ == "__main__":
    main()