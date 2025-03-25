from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import socket
import threading

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

# Nhận khóa công khai từ server
server_public_key = RSA.import_key(client_socket.recv(2048))

# Tạo cặp khóa RSA cho client
client_key = RSA.generate(2048)
client_socket.send(client_key.publickey().export_key(format='PEM'))

# Nhận khóa AES đã mã hóa từ server và giải mã
encrypted_aes_key = client_socket.recv(256)
cipher_rsa = PKCS1_OAEP.new(client_key)
aes_key = cipher_rsa.decrypt(encrypted_aes_key)

def encrypt_message(message):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext

def decrypt_message(encrypted_message):
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode()

def receive_messages():
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                print("Server đã đóng kết nối.")
                break

            decrypted_message = decrypt_message(encrypted_message)
            print(f"\nReceived: {decrypted_message}")
        except ConnectionAbortedError:
            print("Kết nối bị đóng đột ngột.")
            break
        except ConnectionResetError:
            print("Server đã đóng kết nối.")
            break
        except Exception as e:
            print(f"Lỗi khi nhận tin nhắn: {e}")
            break

    client_socket.close()

# Tạo luồng để nhận tin nhắn
receive_thread = threading.Thread(target=receive_messages)
receive_thread.start()

# Vòng lặp gửi tin nhắn
while True:
    message = input("Enter message ('exit' to quit): ")
    if message.lower() == "exit":
        encrypted = encrypt_message(message)
        client_socket.send(encrypted)
        print("Đang đóng kết nối...")
        client_socket.close()
        break
    else:
        encrypted = encrypt_message(message)
        client_socket.send(encrypted)
