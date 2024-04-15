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

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

key = b'sixteen byte key'

while True:
    message = input("Enter message: ")
    encrypted_message = aes_encrypt(message, key)
    client_socket.sendall(encrypted_message)
    data = client_socket.recv(1024)
    print(f"Received message: {data}")
    decrypted_message = aes_decrypt(data, key)
    print(f"Decrypted message: {decrypted_message}")

