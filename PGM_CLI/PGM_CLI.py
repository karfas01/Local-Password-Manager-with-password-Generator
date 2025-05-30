import os
import json
import base64
import hashlib
import random
import string
from cryptography.fernet import Fernet, InvalidToken
from getpass import getpass

MASTER_PASSWORD_FILE = "master_password.hash"
PASSWORDS_FILE = "passwords.dat"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def derive_key(master_password):
    digest = hashlib.sha256(master_password.encode()).digest()
    return base64.urlsafe_b64encode(digest)

def generate_password(length=16, use_special=True):
    chars = string.ascii_letters + string.digits
    if use_special:
        chars += "!@#$%^&*()-_=+[]{}|;:,.<>?/"
    password = [
        random.choice(string.ascii_lowercase),
        random.choice(string.ascii_uppercase),
        random.choice(string.digits)
    ]
    if use_special:
        password.append(random.choice("!@#$%^&*()-_=+[]{}|;:,.<>?/"))
    while len(password) < length:
        password.append(random.choice(chars))
    random.shuffle(password)
    return ''.join(password)

class PasswordManager:
    def __init__(self):
        self.fernet = None
        self.passwords = {}

    def set_master_password(self, master_password):
        with open(MASTER_PASSWORD_FILE, "w") as f:
            f.write(hash_password(master_password))
        self.fernet = Fernet(derive_key(master_password))

    def verify_master_password(self, master_password):
        if not os.path.exists(MASTER_PASSWORD_FILE):
            return False
        with open(MASTER_PASSWORD_FILE, "r") as f:
            stored_hash = f.read()
        if hash_password(master_password) == stored_hash:
            self.fernet = Fernet(derive_key(master_password))
            return True
        return False

    def load_passwords(self):
        if not os.path.exists(PASSWORDS_FILE):
            self.passwords = {}
            return
        try:
            with open(PASSWORDS_FILE, "rb") as f:
                encrypted = f.read()
            decrypted = self.fernet.decrypt(encrypted)
            self.passwords = json.loads(decrypted.decode())
        except (InvalidToken, json.JSONDecodeError):
            print("Ошибка: не удалось расшифровать файл паролей. Возможно, неверный мастер-пароль.")
            exit(1)

    def save_passwords(self):
        data = json.dumps(self.passwords, ensure_ascii=False, indent=4).encode()
        encrypted = self.fernet.encrypt(data)
        with open(PASSWORDS_FILE, "wb") as f:
            f.write(encrypted)

    def add_or_update_password(self, service, login, password):
        self.passwords[service] = {"login": login, "password": password}
        self.save_passwords()
        print(f"Пароль для '{service}' добавлен/обновлён.")

    def delete_password(self, service):
        if service in self.passwords:
            del self.passwords[service]
            self.save_passwords()
            print(f"Пароль для '{service}' удалён.")
        else:
            print(f"Сервис '{service}' не найден.")

    def list_passwords(self):
        if not self.passwords:
            print("Пароли отсутствуют.")
            return
        print("\nСохранённые пароли:")
        for service, creds in self.passwords.items():
            print(f"- {service}: Логин: {creds['login']}, Пароль: {creds['password']}")

    def get_password(self, service):
        if service in self.passwords:
            creds = self.passwords[service]
            print(f"Сервис: {service}\nЛогин: {creds['login']}\nПароль: {creds['password']}")
        else:
            print(f"Сервис '{service}' не найден.")

def main():
    pm = PasswordManager()

    if not os.path.exists(MASTER_PASSWORD_FILE):
        print("Создайте мастер-пароль.")
        while True:
            pwd1 = getpass("Введите новый мастер-пароль (мин. 6 символов): ")
            if len(pwd1) < 6:
                print("Пароль слишком короткий.")
                continue
            pwd2 = getpass("Повторите мастер-пароль: ")
            if pwd1 != pwd2:
                print("Пароли не совпадают.")
                continue
            pm.set_master_password(pwd1)
            print("Мастер-пароль установлен.")
            break
    else:
        for _ in range(3):
            pwd = getpass("Введите мастер-пароль: ")
            if pm.verify_master_password(pwd):
                break
            print("Неверный мастер-пароль.")
        else:
            print("Превышено количество попыток. Выход.")
            return

    pm.load_passwords()

    while True:
        print("\nМеню:")
        print("1. Добавить/обновить пароль")
        print("2. Удалить пароль")
        print("3. Просмотреть все пароли")
        print("4. Получить пароль по сервису")
        print("5. Сгенерировать пароль")
        print("6. Выход")

        choice = input("Выберите действие (1-6): ").strip()

        if choice == "1":
            service = input("Сервис: ").strip()
            login = input("Логин: ").strip()
            pwd = input("Пароль (оставьте пустым для генерации): ").strip()
            if not pwd:
                try:
                    length = int(input("Длина пароля (по умолчанию 16): ").strip() or "16")
                except ValueError:
                    length = 16
                use_special = input("Использовать спецсимволы? (y/n, по умолчанию y): ").strip().lower() != "n"
                pwd = generate_password(length, use_special)
                print(f"Сгенерированный пароль: {pwd}")
            pm.add_or_update_password(service, login, pwd)

        elif choice == "2":
            service = input("Сервис для удаления: ").strip()
            pm.delete_password(service)

        elif choice == "3":
            pm.list_passwords()

        elif choice == "4":
            service = input("Сервис: ").strip()
            pm.get_password(service)

        elif choice == "5":
            try:
                length = int(input("Длина пароля (по умолчанию 16): ").strip() or "16")
            except ValueError:
                length = 16
            use_special = input("Использовать спецсимволы? (y/n, по умолчанию y): ").strip().lower() != "n"
            pwd = generate_password(length, use_special)
            print(f"Сгенерированный пароль: {pwd}")

        elif choice == "6":
            print("Выход.")
            break

        else:
            print("Неверный выбор. Попробуйте снова.")

if __name__ == "__main__":
    main()
