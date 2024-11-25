import socket
import sys
import argparse
import threading
import os

def receive(conn):
    with conn:
        while True:
            data=conn.recv(1024)
            print(data.decode(), end="", flush=True)

def sender(conn):
    while True:
        data = input()
        data = data + "\n"
        conn.sendall(data.encode())

def server_mode(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(5)
        print(f"Listening on port {port}...")
        
        conn, addr = server_socket.accept()
        print(f"Connection from {addr}")
        rec_t = threading.Thread(target=receive, args=[conn, ])
        rec_t.daemon = True
        rec_t.start()

        send_t = threading.Thread(target=sender, args=[conn, ])
        send_t.daemon = True
        send_t.start()
        while True:
            pass

def client_mode(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        print(f"Connected to {host}:{port}")
        
        try:
            while True:
                message = input("Enter message to send (or 'exit' to quit): ")
                if message.lower() == 'exit':
                    break
                client_socket.sendall(message.encode())
                
                data = client_socket.recv(1024)
                print(f"Received: {data.decode()}")
        except KeyboardInterrupt:
            print("Connection closed.")

if __name__ == "__main__":
    description = """\
    connect to somewhere:   nc [-options] hostname port
    listen for inbound:     nc -l -p port [-options]
    """
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
    description=description)
    parser.add_argument("-l", action=argparse.BooleanOptionalAction, default=False, help="listen mode, for inbound connects")
    parser.add_argument("-p", metavar='', type=int, default=80, help="local port number")
    parser.add_argument("ip", type=str, nargs='?', help="local port number")
    parser.add_argument("port", type=int, nargs='?', help="local port number")

    args = parser.parse_args()

    if args.l == True:
        server_mode(args.p)
    elif args.l == False:
        client_mode(args.ip, args.p)