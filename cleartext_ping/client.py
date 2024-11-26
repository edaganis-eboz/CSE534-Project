import socket

import time
def main():
    server_addr = ('127.0.0.1', 1337)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(server_addr)
        for _ in range(100):
            try:
                message = str(time.time()).encode()
                s.sendall(message)
                time.sleep(0.1)
            except Exception as e:
                pass
        s.close()



if __name__ == "__main__":
    main()