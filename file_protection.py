
import os
import getpass
import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


MAGIC = b"FILEPROTECT1"
SALT_SIZE = 16


def generate_key(password, salt):

    # Generate encryption key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000
    )

    key = base64.urlsafe_b64encode(
        kdf.derive(password.encode())
    )

    return Fernet(key)


def protect_file():

    file_path = input("\nEnter file path: ").strip().strip('"')

    if not os.path.isfile(file_path):
        print("Error: File not found!")
        return

    password = getpass.getpass("Create protection password: ")

    if len(password) < 8:
        print("Password must contain at least 8 characters.")
        return

    confirm = getpass.getpass("Confirm password: ")

    if password != confirm:
        print("Passwords do not match!")
        return

    salt = os.urandom(SALT_SIZE)

    try:
        with open(file_path, "rb") as file:
            data = file.read()

        cipher = generate_key(password, salt)

        encrypted_data = cipher.encrypt(data)

        output_path = file_path + ".protected"

        if os.path.exists(output_path):
            print("Protected output file already exists!")
            return

        with open(output_path, "wb") as file:
            file.write(MAGIC + salt + encrypted_data)

        print("\nFile protected successfully!")
        print("Protected file:", output_path)

    except OSError as error:
        print("File error:", error)


def restore_file():

    file_path = input("\nEnter protected file path: ").strip().strip('"')

    if not os.path.isfile(file_path):
        print("Error: File not found!")
        return

    password = getpass.getpass("Enter protection password: ")

    try:
        with open(file_path, "rb") as file:
            content = file.read()

        if not content.startswith(MAGIC):
            print("Invalid protected file format!")
            return

        start = len(MAGIC)

        salt = content[start:start + SALT_SIZE]
        encrypted_data = content[start + SALT_SIZE:]

        cipher = generate_key(password, salt)

        original_data = cipher.decrypt(encrypted_data)

        output_path = file_path[:-len(".protected")]

        if os.path.exists(output_path):
            output_path += ".restored"

        with open(output_path, "wb") as file:
            file.write(original_data)

        print("\nFile restored successfully!")
        print("Restored file:", output_path)

    except InvalidToken:
        print("\nIncorrect password or damaged file!")

    except OSError as error:
        print("File error:", error)


def main():

    print("=" * 45)
    print("          FILE PROTECTION UTILITY")
    print("=" * 45)

    while True:

        print("\n1. Protect a File")
        print("2. Restore a File")
        print("3. Exit")

        choice = input("\nEnter your choice: ")

        if choice == "1":
            protect_file()

        elif choice == "2":
            restore_file()

        elif choice == "3":
            print("\nThank you for using File Protection Utility!")
            break

        else:
            print("\nInvalid choice! Please select 1, 2 or 3.")


if __name__ == "__main__":
    main()
