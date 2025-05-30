import ttkbootstrap as tb
from ttkbootstrap.constants import *
import tkinter as tk
from tkinter import messagebox, simpledialog
import os
import json
import hashlib
import base64
from cryptography.fernet import Fernet, InvalidToken
import random
import string
import pandas as pd

MASTER_PASSWORD_FILE = "master_password.hash"
PASSWORDS_FILE = "passwords.dat"

class PasswordStorage:
    def __init__(self):
        self.master_password_file = MASTER_PASSWORD_FILE
        self.passwords_file = PASSWORDS_FILE
        self.fernet = None
        self.passwords = []

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def derive_key(self, master_password):
        digest = hashlib.sha256(master_password.encode()).digest()
        return base64.urlsafe_b64encode(digest)

    def set_master_password(self, master_password):
        with open(self.master_password_file, "w") as f:
            f.write(self.hash_password(master_password))
        self.fernet = Fernet(self.derive_key(master_password))

    def verify_master_password(self, master_password):
        if not os.path.exists(self.master_password_file):
            return False
        with open(self.master_password_file, "r") as f:
            stored_hash = f.read()
        if self.hash_password(master_password) == stored_hash:
            self.fernet = Fernet(self.derive_key(master_password))
            return True
        return False

    def load_passwords(self):
        if not os.path.exists(self.passwords_file):
            self.passwords = []
            return
        try:
            with open(self.passwords_file, "rb") as f:
                encrypted = f.read()
            decrypted = self.fernet.decrypt(encrypted)
            self.passwords = json.loads(decrypted.decode())
        except (InvalidToken, json.JSONDecodeError):
            raise ValueError("Ошибка расшифровки. Неверный мастер-пароль?")

    def save_passwords(self):
        data = json.dumps(self.passwords, ensure_ascii=False, indent=4).encode()
        encrypted = self.fernet.encrypt(data)
        with open(self.passwords_file, "wb") as f:
            f.write(encrypted)

    def add_or_update(self, service, login, password):
        for item in self.passwords:
            if item["service"].lower() == service.lower() and item["login"].lower() == login.lower():
                item["password"] = password
                return "updated"
        self.passwords.append({"service": service, "login": login, "password": password})
        return "added"

    def delete(self, service, login):
        before = len(self.passwords)
        self.passwords = [p for p in self.passwords if not (p["service"].lower() == service.lower() and p["login"].lower() == login.lower())]
        return len(self.passwords) < before

    def get_all(self):
        return self.passwords.copy()

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Менеджер Паролей")
        self.root.geometry("600x700")
        self.root.resizable(False, False)

        self.storage = PasswordStorage()
        if not self.check_master_password():
            self.root.destroy()
            return
        try:
            self.storage.load_passwords()
        except ValueError as e:
            messagebox.showerror("Ошибка", str(e))
            self.root.destroy()
            return

        self.build_ui()
        self.refresh_treeview()

    def check_master_password(self):
        if not os.path.exists(MASTER_PASSWORD_FILE):
            while True:
                pwd1 = simpledialog.askstring("Создание мастер-пароля", "Введите новый мастер-пароль (мин. 6 символов):", show='*', parent=self.root)
                if pwd1 is None:
                    return False
                if len(pwd1) < 6:
                    messagebox.showwarning("Внимание", "Пароль слишком короткий.")
                    continue
                pwd2 = simpledialog.askstring("Подтверждение", "Повторите мастер-пароль:", show='*', parent=self.root)
                if pwd1 != pwd2:
                    messagebox.showerror("Ошибка", "Пароли не совпадают.")
                    continue
                self.storage.set_master_password(pwd1)
                messagebox.showinfo("Готово", "Мастер-пароль установлен.")
                return True
        else:
            for _ in range(3):
                pwd = simpledialog.askstring("Мастер-пароль", "Введите мастер-пароль:", show='*', parent=self.root)
                if pwd is None:
                    return False
                if self.storage.verify_master_password(pwd):
                    return True
                messagebox.showerror("Ошибка", "Неверный мастер-пароль.")
            messagebox.showerror("Ошибка", "Превышено количество попыток.")
            return False

    def build_ui(self):
        frame_inputs = tb.Labelframe(self.root, text="Данные для генерации / добавления", bootstyle=INFO)
        frame_inputs.pack(fill='x', padx=20, pady=10)

        tb.Label(frame_inputs, text="Сервис:", font=("Segoe UI", 12)).grid(row=0, column=0, sticky='w', padx=10, pady=5)
        self.entry_service = tb.Entry(frame_inputs, width=40, font=("Segoe UI", 12))
        self.entry_service.grid(row=0, column=1, padx=10, pady=5)

        tb.Label(frame_inputs, text="Логин:", font=("Segoe UI", 12)).grid(row=1, column=0, sticky='w', padx=10, pady=5)
        self.entry_login = tb.Entry(frame_inputs, width=40, font=("Segoe UI", 12))
        self.entry_login.grid(row=1, column=1, padx=10, pady=5)

        tb.Label(frame_inputs, text="Длина пароля:", font=("Segoe UI", 12)).grid(row=2, column=0, sticky='w', padx=10, pady=5)
        self.spin_length = tb.Spinbox(frame_inputs, from_=8, to=64, width=6, font=("Segoe UI", 12))
        self.spin_length.grid(row=2, column=1, sticky='w', padx=10, pady=5)
        self.spin_length.delete(0, tk.END)
        self.spin_length.insert(0, "16")

        self.var_special = tk.BooleanVar(value=True)
        self.check_special = tb.Checkbutton(frame_inputs, text="Использовать спецсимволы", variable=self.var_special, bootstyle=SUCCESS)
        self.check_special.grid(row=3, column=1, sticky='w', padx=10, pady=5)

        tb.Button(frame_inputs, text="Сгенерировать пароль", command=self.on_generate, bootstyle=PRIMARY).grid(row=4, column=0, pady=15, padx=10)
        tb.Button(frame_inputs, text="Добавить / Обновить пароль", command=self.on_add_or_update, bootstyle=SUCCESS).grid(row=4, column=1, pady=15, padx=10)

        frame_password = tb.Labelframe(self.root, text="Пароль", bootstyle=INFO)
        frame_password.pack(fill='x', padx=20, pady=10)

        self.entry_password = tb.Entry(frame_password, width=40, font=('Consolas', 14), bootstyle=INFO)
        self.entry_password.pack(side='left', padx=10, pady=10, fill='x', expand=True)

        tb.Button(frame_password, text="📋 Copy", command=self.copy_password, bootstyle=(SUCCESS, OUTLINE)).pack(side='right', padx=10)

        frame_table = tb.Labelframe(self.root, text="Сохранённые пароли", bootstyle=INFO)
        frame_table.pack(fill='both', expand=True, padx=20, pady=10)

        columns = ("service", "login", "password")
        self.tree = tb.Treeview(frame_table, columns=columns, show="headings", selectmode="browse")
        for col in columns:
            self.tree.heading(col, text=col.capitalize())
            self.tree.column(col, width=150 if col != "password" else 200)
        self.tree.pack(fill='both', expand=True, side='left')

        scrollbar = tb.Scrollbar(frame_table, command=self.tree.yview)
        scrollbar.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        frame_buttons = tb.Frame(self.root)
        frame_buttons.pack(pady=10)

        tb.Button(frame_buttons, text="Удалить выбранный", command=self.delete_selected, bootstyle=DANGER).pack(side='left', padx=10)
        tb.Button(frame_buttons, text="Экспортировать в Excel", command=self.export_to_excel, bootstyle=SECONDARY).pack(side='left', padx=10)

    def generate_password(self, length=16, use_special=True):
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

    def on_generate(self):
        try:
            length = int(self.spin_length.get())
            if length < 8:
                raise ValueError
        except ValueError:
            messagebox.showerror("Ошибка", "Длина пароля должна быть числом от 8 и выше.")
            return
        pwd = self.generate_password(length, self.var_special.get())
        self.entry_password.delete(0, tk.END)
        self.entry_password.insert(0, pwd)

    def on_add_or_update(self):
        service = self.entry_service.get().strip()
        login = self.entry_login.get().strip()
        password = self.entry_password.get().strip()
        if not service or not login or not password:
            messagebox.showwarning("Внимание", "Заполните все поля: Сервис, Логин, Пароль.")
            return
        result = self.storage.add_or_update(service, login, password)
        self.storage.save_passwords()
        messagebox.showinfo("Готово", f"Пароль для {service} {'обновлён' if result=='updated' else 'добавлен'}.")
        self.refresh_treeview()

    def refresh_treeview(self):
        self.tree.delete(*self.tree.get_children())
        for item in self.storage.get_all():
            self.tree.insert("", tk.END, values=(item["service"], item["login"], item["password"]))

    def on_tree_select(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        service, login, password = self.tree.item(selected[0])["values"]
        self.entry_service.delete(0, tk.END)
        self.entry_service.insert(0, service)
        self.entry_login.delete(0, tk.END)
        self.entry_login.insert(0, login)
        self.entry_password.delete(0, tk.END)
        self.entry_password.insert(0, password)

    def delete_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Внимание", "Выберите запись для удаления.")
            return
        service, login, _ = self.tree.item(selected[0])["values"]
        if messagebox.askyesno("Подтверждение", f"Удалить пароль для сервиса '{service}' и логина '{login}'?"):
            if self.storage.delete(service, login):
                self.storage.save_passwords()
                self.refresh_treeview()
                messagebox.showinfo("Удалено", "Запись удалена.")
            else:
                messagebox.showwarning("Внимание", "Запись не найдена.")

    def copy_password(self):
        pwd = self.entry_password.get()
        if pwd:
            self.root.clipboard_clear()
            self.root.clipboard_append(pwd)
            messagebox.showinfo("Скопировано", "Пароль скопирован в буфер обмена.")
        else:
            messagebox.showwarning("Внимание", "Пароль отсутствует.")

    def export_to_excel(self):
        passwords = self.storage.get_all()
        if not passwords:
            messagebox.showwarning("Внимание", "Нет паролей для экспорта.")
            return
        try:
            df = pd.DataFrame(passwords)
            df.to_excel("passwords_export.xlsx", index=False)
            messagebox.showinfo("Экспорт", "Пароли экспортированы в файл passwords_export.xlsx")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось экспортировать: {e}")

if __name__ == "__main__":
    root = tb.Window(themename="darkly")
    app = PasswordManagerApp(root)
    root.mainloop()
