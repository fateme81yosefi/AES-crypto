from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import socket

HOST = '127.0.0.1'
PORT = 12345

def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    iv = cipher.iv
    return iv + ct_bytes

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen()

print("Server is listening...")

client_socket, client_address = server_socket.accept()
print(f"Connection from {client_address}")

key = b'sixteen byte key'

while True:
    data = client_socket.recv(1024)
    if not data:
        break
    decrypted_message = aes_decrypt(data, key)
    print(f"Received message: {decrypted_message}")
    encrypted_message = aes_encrypt(decrypted_message, key)
    client_socket.sendall(encrypted_message)

client_socket.close()

