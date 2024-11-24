import socket
import time
def main():
    total: float = 0.0
    ip = "127.0.0.1"
    port = 1337
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((ip, port))
        s.listen(5)

        while True:
            client_socket, client_addr = s.accept()
            count: int = 0
            # print(f'Connected to {client_addr}')
            try:
                data = client_socket.recv(1024)
                if data:
                    plaintext = float(data)
                    oopt = time.time() - plaintext
                    print(f"One way ping: {oopt}")
                    total += oopt
                    count += 1
            except KeyboardInterrupt:
                s.close()
                break
            except Exception as e:
                print(f"{e}")
            
            if count >= 100:
                print(f"{count} pings reached avg is :{total / count}")
                s.close()
                break
            
    
    


if __name__ == "__main__":
    main()