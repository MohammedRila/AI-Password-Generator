import json
import getpass
import hashlib
from cryptography.fernet import Fernet
import logging

class PasswordManager:
    def __init__(self, filename, master_key):
        self.filename = filename
        self.passwords = {}
        self.master_key = master_key
        self.logger = self._setup_logger()

    def _setup_logger(self):
        logger = logging.getLogger('PasswordManager')
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler = logging.FileHandler('audit.log')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        return logger

    def create_master_password(self):
        while True:
            password = getpass.getpass("Create a master password: ")
            confirm_password = getpass.getpass("Confirm master password: ")
            if password == confirm_password:
                self.master_key = hashlib.sha256(password.encode()).digest()
                self.logger.info('Master password created.')
                print("Master password created successfully.")
                break
            else:
                print("Passwords do not match. Please try again.")

    def authenticate(self):
        password = getpass.getpass("Enter master password: ")
        hashed_password = hashlib.sha256(password.encode()).digest()
        if hashed_password == self.master_key:
            return True
        else:
            print("Incorrect master password.")
            return False

    def create_password(self, website, username, password):
        if self.authenticate() and self._has_permission('create_password'):
            if website in self.passwords:
                print("Password already exists for this website.")
            else:
                if self._is_strong_password(password):
                    self.passwords[website] = {
                        'username': username,
                        'password': password
                    }
                    self._save_passwords()
                    self.logger.info('Password created for website: %s', website)
                    print("Password created successfully.")
                else:
                    print("Password does not meet the requirements.")
        else:
            print("Access denied. You do not have permission to create a password.")

    def get_password(self, website):
        if self.authenticate() and self._has_permission('get_password'):
            if website in self.passwords:
                password = self.passwords[website]['password']
                self.logger.info('Password retrieved for website: %s', website)
                print("Password:", password)
            else:
                print("Password not found for this website.")
        else:
            print("Access denied. You do not have permission to retrieve passwords.")

    def delete_password(self, website):
        if self.authenticate() and self._has_permission('delete_password'):
            if website in self.passwords:
                confirm = input("Are you sure you want to delete the password for {}? (yes/no): ".format(website))
                if confirm.lower() == 'yes':
                    del self.passwords[website]
                    self._save_passwords()
                    self.logger.info('Password deleted for website: %s', website)
                    print("Password deleted successfully.")
                else:
                    print("Deletion cancelled.")
            else:
                print("Password not found for this website.")
        else:
            print("Access denied. You do not have permission to delete passwords.")

    def reset_master_password(self):
        if self.authenticate() and self._has_permission('reset_master_password'):
            while True:
                new_password = getpass.getpass("Enter a new master password: ")
                confirm_password = getpass.getpass("Confirm new master password: ")
                if new_password == confirm_password:
                    self.master_key = hashlib.sha256(new_password.encode()).digest()
                    self.logger.info('Master password reset.')
                    print("Master password reset successfully.")
                    break
                else:
                    print("Passwords do not match. Please try again.")
        else:
            print("Access denied. You do not have permission to reset the master password.")

    def _has_permission(self, action):
        # Implement RBAC logic to check if the user has permission for the action
        # Return True if the user has permission, False otherwise
        # You can customize this method to implement RBAC based on user roles and permissions
        # Example implementation:
        # if user_role == 'admin' and action in ['create_password', 'get_password', 'delete_password', 'reset_master_password']:
        #     return True
        # elif user_role == 'user' and action in ['get_password']:
        #     return True
        # else:
        #     return False
        return True

    def _is_strong_password(self, password):
        # Implement your own password strength requirements here
        # For example, check length, complexity, and other criteria
        return len(password) >= 8

    def _save_passwords(self):
        encrypted_passwords = self._encrypt_data(json.dumps(self.passwords))
        with open(self.filename, 'wb') as file:
            file.write(encrypted_passwords)

    def _load_passwords(self):
        try:
            with open(self.filename, 'rb') as file:
                encrypted_passwords = file.read()
                self.passwords = json.loads(self._decrypt_data(encrypted_passwords))
        except FileNotFoundError:
            self.passwords = {}

    def _encrypt_data(self, data):
        cipher = Fernet(self.master_key)
        encrypted_data = cipher.encrypt(data.encode())
        return encrypted_data

    def _decrypt_data(self, encrypted_data):
        cipher = Fernet(self.master_key)
        decrypted_data = cipher.decrypt(encrypted_data)
        return decrypted_data.decode()

def main():
    filename = 'passwords.dat'
    master_key = None
    password_manager = PasswordManager(filename, master_key)
    password_manager.create_master_password()
    password_manager._load_passwords()

    while True:
        print("\nPassword Manager")
        print("1. Create a new password")
        print("2. Retrieve a password")
        print("3. Delete a password")
        print("4. Reset master password")
        print("5. Quit")

        choice = input("Enter your choice: ")

        if choice == '1':
            website = input("Enter the website: ")
            username = input("Enter the username: ")
            password = getpass.getpass("Enter the password: ")
            password_manager.create_password(website, username, password)
        elif choice == '2':
            website = input("Enter the website: ")
            password_manager.get_password(website)
        elif choice == '3':
            website = input("Enter the website: ")
            password_manager.delete_password(website)
        elif choice == '4':
            password_manager.reset_master_password()
        elif choice == '5':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == '__main__':
    main()
