import hashlib
import os
from cryptography.fernet import Fernet

class PasswordManager:
    def __init__(self):
        self.key = self.load_or_generate_key()
        self.passwords_file = 'passwords.txt'
    
    def load_or_generate_key(self):
        key_file = 'key.key'
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
        return key
    
    def encrypt_password(self, password):
        cipher = Fernet(self.key)
        encrypted_password = cipher.encrypt(password.encode())
        return encrypted_password
    
    def decrypt_password(self, encrypted_password):
        cipher = Fernet(self.key)
        decrypted_password = cipher.decrypt(encrypted_password).decode()
        return decrypted_password
    
    def store_password(self, username, email, password):
        with open(self.passwords_file, 'a') as file:
            encrypted_password = self.encrypt_password(password)
            file.write(f'Username: {username}, Email: {email}, Password: {encrypted_password}\n')
    
    def retrieve_password(self, username):
        with open(self.passwords_file, 'r') as file:
            for line in file:
                if username in line:
                    encrypted_password = line.split('Password: ')[1].encode()
                    return encrypted_password
    
    def authenticate_user(self, username, password):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        stored_password = self.retrieve_password(username)
        if stored_password:
            decrypted_password = self.decrypt_password(stored_password)
            if hashed_password == decrypted_password:
                return True
        return False
    
    def change_master_password(self):
        new_password = input("Enter new master password: ")
        hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
        with open('master_password.txt', 'w') as file:
            file.write(hashed_password)
        print("Master password changed successfully!")
    
    def run(self):
        username = input("Enter username: ")
        password = input("Enter password: ")
        if self.authenticate_user(username, password):
            print("Authentication successful.")
            # Allow user to manage passwords
            self.change_master_password()
        else:
            print("Authentication failed. Please try again.")

if __name__ == "__main__":
    password_manager = PasswordManager()
    password_manager.run()
