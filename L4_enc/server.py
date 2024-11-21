import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import time
def main():
    key = b'AAAAAAAAAAAAAAAA'
    cipher = AES.new(key, AES.MODE_CBC)
    ip = "127.0.0.1"
    port = 1337
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((ip, port))
        s.listen(5)

        while True:
            client_socket, client_addr = s.accept()
            print(f'Connected to {client_addr}')
            try:
                data = s.recv(1024)
                if data:
                    plaintext = float(unpad(cipher.decrypt(data),16))
                    print(f"One way ping: {time.time() - plaintext}")
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"{e}")
            
    
    


if __name__ == "__main__":
    main()