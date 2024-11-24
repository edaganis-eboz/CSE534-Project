import socket
import time
def main():
    
    ip = "127.0.0.1"
    port = 1337
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((ip, port))
        s.listen(5)

        while True:
            client_socket, client_addr = s.accept()
            # print(f'Connected to {client_addr}')
            try:
                data = client_socket.recv(1024)
                if data:
                    plaintext = float(data)
                    print(f"One way ping: {time.time() - plaintext}")
            except KeyboardInterrupt:
                s.close()
                break
            except Exception as e:
                print(f"{e}")
            
    
    


if __name__ == "__main__":
    main()