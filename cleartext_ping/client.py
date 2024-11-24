import socket

import time
def main():
    server_addr = ('127.0.0.1', 1337)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(server_addr)
        message = str(time.time()).encode()
        s.sendall(message)
        s.close()



if __name__ == "__main__":
    main()