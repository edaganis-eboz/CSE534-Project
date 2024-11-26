import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import time
def main():
    key = b'AAAAAAAAAAAAAAAA'
    cipher = AES.new(key, AES.MODE_CBC)
    server_addr = ('127.0.0.1', 1337)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(server_addr)
        for _ in range(100):
            try:
                message = str(time.time()).encode()
                ciphertext = cipher.encrypt(pad(message, 16))
                s.sendall(cipher.iv + ciphertext)
                time.sleep(0.1)
            except Exception as e:
                pass
        s.close()



if __name__ == "__main__":
    main()