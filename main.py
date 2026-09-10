"""Aplicação de autenticação local com CustomTkinter e SQLite."""

from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import json
import os
import re
import shutil
import sqlite3
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tkinter import filedialog, messagebox
from urllib.error import URLError
from urllib.request import urlopen

import customtkinter as ctk
from PIL import Image

APP_DIR = Path(__file__).resolve().parent
DATABASE_FILE = APP_DIR / "usuarios.db"
PHOTOS_DIR = APP_DIR / "fotos_perfil"
PBKDF2_ITERATIONS = 600_000


class UserDatabase:
    """Camada pequena e isolada para o banco de usuários."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self._create_table()

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _create_table(self) -> None:
        connection = self._connection()
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS usuarios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    usuario TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    senha_hash TEXT NOT NULL,
                    cpf TEXT UNIQUE,
                    cep TEXT,
                    logradouro TEXT,
                    numero TEXT,
                    complemento TEXT,
                    bairro TEXT,
                    cidade TEXT,
                    uf TEXT,
                    foto_path TEXT,
                    estado_civil TEXT,
                    cor_pele TEXT,
                    papel TEXT NOT NULL DEFAULT 'usuario',
                    ativo INTEGER NOT NULL DEFAULT 1,
                    falhas_login INTEGER NOT NULL DEFAULT 0,
                    bloqueado_ate TEXT,
                    criado_em TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            existing_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(usuarios)")
            }
            new_columns = {
                "cpf": "TEXT",
                "cep": "TEXT",
                "logradouro": "TEXT",
                "numero": "TEXT",
                "complemento": "TEXT",
                "bairro": "TEXT",
                "cidade": "TEXT",
                "uf": "TEXT",
                "foto_path": "TEXT",
                "estado_civil": "TEXT",
                "cor_pele": "TEXT",
                "papel": "TEXT NOT NULL DEFAULT 'usuario'",
                "ativo": "INTEGER NOT NULL DEFAULT 1",
                "falhas_login": "INTEGER NOT NULL DEFAULT 0",
                "bloqueado_ate": "TEXT",
            }
            for column, definition in new_columns.items():
                if column not in existing_columns:
                    connection.execute(f"ALTER TABLE usuarios ADD COLUMN {column} {definition}")
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_usuarios_cpf "
                "ON usuarios(cpf) WHERE cpf IS NOT NULL"
            )
            if not connection.execute("SELECT 1 FROM usuarios WHERE papel = 'admin'").fetchone():
                connection.execute("UPDATE usuarios SET papel = 'admin' WHERE id = (SELECT MIN(id) FROM usuarios)")
            connection.commit()
        finally:
            connection.close()

    @staticmethod
    def _hash_password(password: str, salt: bytes | None = None) -> str:
        salt = salt or os.urandom(16)
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )
        return f"{base64.b64encode(salt).decode()}${base64.b64encode(password_hash).decode()}"

    @staticmethod
    def _verify_password(password: str, stored_value: str) -> bool:
        try:
            salt_text, hash_text = stored_value.split("$", maxsplit=1)
            salt = base64.b64decode(salt_text)
            expected_hash = base64.b64decode(hash_text)
        except (ValueError, base64.binascii.Error):
            return False
        candidate_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )
        return hmac.compare_digest(candidate_hash, expected_hash)

    def create_user(self, username: str, password: str, data: dict[str, str]) -> bool:
        connection = self._connection()
        try:
            role = "admin" if not connection.execute("SELECT 1 FROM usuarios WHERE papel = 'admin'").fetchone() else "usuario"
            connection.execute(
                """INSERT INTO usuarios
                (usuario, senha_hash, cpf, cep, logradouro, numero, complemento, bairro, cidade, uf,
                 foto_path, estado_civil, cor_pele, papel)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    username, self._hash_password(password), data["cpf"], data["cep"],
                    data["logradouro"], data["numero"], data["complemento"],
                    data["bairro"], data["cidade"], data["uf"],
                    data.get("foto_path", ""), data.get("estado_civil", ""), data.get("cor_pele", ""),
                    role,
                ),
            )
            connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            connection.close()

    def authenticate(self, username: str, password: str) -> tuple[bool, str]:
        connection = self._connection()
        try:
            record = connection.execute(
                "SELECT * FROM usuarios WHERE usuario = ?", (username,)
            ).fetchone()
            if record is None or not record["ativo"]:
                return False, "Usuário ou senha inválidos."
            if record["bloqueado_ate"] and datetime.fromisoformat(record["bloqueado_ate"]) > datetime.now(UTC):
                return False, "Conta temporariamente bloqueada. Tente novamente em 15 minutos."
            if self._verify_password(password, record["senha_hash"]):
                connection.execute("UPDATE usuarios SET falhas_login = 0, bloqueado_ate = NULL WHERE id = ?", (record["id"],))
                connection.commit()
                return True, ""
            failures = record["falhas_login"] + 1
            lock_until = (datetime.now(UTC) + timedelta(minutes=15)).isoformat() if failures >= 5 else None
            connection.execute("UPDATE usuarios SET falhas_login = ?, bloqueado_ate = ? WHERE id = ?", (failures, lock_until, record["id"]))
            connection.commit()
            return False, "Conta bloqueada por 15 minutos." if lock_until else "Usuário ou senha inválidos."
        finally:
            connection.close()

    def change_password_with_cpf(self, username: str, cpf: str, password: str) -> bool:
        connection = self._connection()
        try:
            result = connection.execute("UPDATE usuarios SET senha_hash = ?, falhas_login = 0, bloqueado_ate = NULL WHERE usuario = ? AND cpf = ?", (self._hash_password(password), username, cpf)).rowcount
            connection.commit()
            return result == 1
        finally:
            connection.close()

    def list_users(self, term: str = "") -> list[sqlite3.Row]:
        connection = self._connection()
        try:
            like = f"%{term.strip()}%"
            return connection.execute("SELECT * FROM usuarios WHERE usuario LIKE ? OR cpf LIKE ? OR cidade LIKE ? ORDER BY criado_em DESC", (like, like, like)).fetchall()
        finally:
            connection.close()

    def set_active(self, username: str, active: bool) -> None:
        connection = self._connection()
        try:
            connection.execute("UPDATE usuarios SET ativo = ? WHERE usuario = ?", (int(active), username))
            connection.commit()
        finally:
            connection.close()

    def export_csv(self, path: str) -> int:
        users = self.list_users()
        columns = ["usuario", "cpf", "papel", "ativo", "cidade", "uf", "estado_civil", "cor_pele", "criado_em"]
        with open(path, "w", newline="", encoding="utf-8-sig") as file:
            writer = csv.DictWriter(file, fieldnames=columns)
            writer.writeheader()
            writer.writerows({column: user[column] for column in columns} for user in users)
        return len(users)

    def get_user(self, username: str) -> sqlite3.Row | None:
        connection = self._connection()
        try:
            return connection.execute("SELECT * FROM usuarios WHERE usuario = ?", (username,)).fetchone()
        finally:
            connection.close()

    def update_user(self, username: str, data: dict[str, str]) -> bool:
        connection = self._connection()
        try:
            connection.execute(
                """UPDATE usuarios SET cpf = ?, cep = ?, logradouro = ?, numero = ?,
                complemento = ?, bairro = ?, cidade = ?, uf = ?, foto_path = ?,
                estado_civil = ?, cor_pele = ? WHERE usuario = ?""",
                (data["cpf"], data["cep"], data["logradouro"], data["numero"],
                 data["complemento"], data["bairro"], data["cidade"], data["uf"],
                 data["foto_path"], data["estado_civil"], data["cor_pele"], username),
            )
            connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            connection.close()


class AuthApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.database = UserDatabase(DATABASE_FILE)
        self.current_user = ""

        self.title("Acesso Seguro")
        self.geometry("980x720")
        self.minsize(800, 600)
        self.configure(fg_color=("#f5f7fb", "#10131c"))
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.show_login()

    def _clear_screen(self) -> None:
        for widget in self.winfo_children():
            widget.destroy()

    def _build_shell(self, title: str, subtitle: str) -> ctk.CTkFrame:
        self._clear_screen()
        shell = ctk.CTkFrame(self, corner_radius=20, fg_color=("#ffffff", "#1b2130"))
        shell.grid(row=0, column=0, padx=36, pady=36, sticky="nsew")
        shell.grid_columnconfigure((0, 1), weight=1)
        shell.grid_rowconfigure(0, weight=1)

        side = ctk.CTkFrame(shell, corner_radius=16, fg_color=("#3156d9", "#2848b9"))
        side.grid(row=0, column=0, padx=(22, 11), pady=22, sticky="nsew")
        side.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(side, text="PORTAL", font=ctk.CTkFont(size=15, weight="bold"), text_color="#cbd7ff").grid(row=0, column=0, padx=32, pady=(46, 5), sticky="w")
        ctk.CTkLabel(side, text="Sua conta,\nseu espaço.", font=ctk.CTkFont(size=34, weight="bold"), justify="left", text_color="white").grid(row=1, column=0, padx=32, sticky="w")
        ctk.CTkLabel(side, text="Entre com segurança ou crie uma nova conta para começar.", font=ctk.CTkFont(size=14), justify="left", wraplength=230, text_color="#e5eaff").grid(row=2, column=0, padx=32, pady=(16, 40), sticky="nw")

        form = ctk.CTkScrollableFrame(shell, fg_color="transparent")
        form.grid(row=0, column=1, padx=(34, 46), pady=38, sticky="nsew")
        form.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(form, text=title, font=ctk.CTkFont(size=28, weight="bold")).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(form, text=subtitle, font=ctk.CTkFont(size=14), text_color=("#65708a", "#abb4c6"), wraplength=300, justify="left").grid(row=1, column=0, pady=(6, 26), sticky="w")
        return form

    def _field(self, parent: ctk.CTkFrame, row: int, label: str, password: bool = False) -> ctk.CTkEntry:
        ctk.CTkLabel(parent, text=label, font=ctk.CTkFont(size=13, weight="bold")).grid(row=row, column=0, pady=(10, 6), sticky="w")
        entry = ctk.CTkEntry(parent, height=42, placeholder_text=label, show="•" if password else "")
        entry.grid(row=row + 1, column=0, sticky="ew")
        return entry

    @staticmethod
    def _only_digits(value: str) -> str:
        return re.sub(r"\D", "", value)

    @classmethod
    def _is_valid_cpf(cls, cpf: str) -> bool:
        cpf = cls._only_digits(cpf)
        if len(cpf) != 11 or cpf == cpf[0] * 11:
            return False
        for position in (9, 10):
            total = sum(int(cpf[index]) * (position + 1 - index) for index in range(position))
            digit = (total * 10 % 11) % 10
            if digit != int(cpf[position]):
                return False
        return True

    @staticmethod
    def _is_strong_password(password: str) -> bool:
        return len(password) >= 8 and any(char.isupper() for char in password) and any(char.isdigit() for char in password)

    def _format_cpf(self, _event=None) -> None:
        entry = self.registration_fields["cpf"]
        digits = self._only_digits(entry.get())[:11]
        if len(digits) == 11:
            entry.delete(0, "end")
            entry.insert(0, f"{digits[:3]}.{digits[3:6]}.{digits[6:9]}-{digits[9:]}")

    def _format_cep(self, _event=None) -> None:
        entry = self.registration_fields["cep"]
        digits = self._only_digits(entry.get())[:8]
        entry.delete(0, "end")
        entry.insert(0, f"{digits[:5]}-{digits[5:]}" if len(digits) > 5 else digits)
        if len(digits) == 8:
            self.search_cep()

    def search_cep(self) -> None:
        cep = self._only_digits(self.registration_fields["cep"].get())
        if len(cep) != 8:
            self.cep_status.configure(text="Informe um CEP com 8 dígitos.", text_color="#d97706")
            return
        self.cep_status.configure(text="Buscando endereço...", text_color=("#65708a", "#abb4c6"))
        threading.Thread(target=self._request_cep, args=(cep,), daemon=True).start()

    def _request_cep(self, cep: str) -> None:
        try:
            with urlopen(f"https://viacep.com.br/ws/{cep}/json/", timeout=8) as response:
                result = json.load(response)
            if result.get("erro"):
                raise ValueError("CEP não encontrado.")
        except (URLError, TimeoutError, ValueError, json.JSONDecodeError):
            self.after(0, self._cep_error)
            return
        self.after(0, lambda: self._fill_address(result))

    def _cep_error(self) -> None:
        self.cep_status.configure(
            text="Não foi possível localizar o CEP. Confira o número ou sua conexão.",
            text_color="#dc2626",
        )

    def _fill_address(self, result: dict) -> None:
        field_map = {
            "logradouro": result.get("logradouro", ""),
            "bairro": result.get("bairro", ""),
            "cidade": result.get("localidade", ""),
            "uf": result.get("uf", ""),
        }
        for name, value in field_map.items():
            entry = self.registration_fields[name]
            entry.delete(0, "end")
            entry.insert(0, value)
        self.cep_status.configure(text="Endereço preenchido automaticamente.", text_color="#16a34a")
        self.registration_fields["numero"].focus()

    def _choose_photo(self, field_name: str) -> None:
        filename = filedialog.askopenfilename(
            title="Selecionar foto de perfil",
            filetypes=[("Imagens", "*.png *.jpg *.jpeg *.webp"), ("Todos os arquivos", "*.*")],
        )
        if filename:
            entry = self.registration_fields[field_name]
            entry.delete(0, "end")
            entry.insert(0, filename)

    @staticmethod
    def _store_photo(source_path: str) -> str:
        if not source_path or not Path(source_path).is_file():
            return source_path if source_path and Path(source_path).parent == PHOTOS_DIR else ""
        suffix = Path(source_path).suffix.lower()
        if suffix not in {".png", ".jpg", ".jpeg", ".webp"}:
            raise ValueError("Escolha uma imagem PNG, JPG, JPEG ou WEBP.")
        PHOTOS_DIR.mkdir(exist_ok=True)
        destination = PHOTOS_DIR / f"{uuid.uuid4().hex}{suffix}"
        shutil.copy2(source_path, destination)
        return str(destination)

    def _add_photo_selector(self, form, row: int, initial_value: str = "") -> int:
        ctk.CTkLabel(form, text="Foto de perfil", font=ctk.CTkFont(size=13, weight="bold")).grid(row=row, column=0, pady=(10, 6), sticky="w")
        photo_row = ctk.CTkFrame(form, fg_color="transparent")
        photo_row.grid(row=row + 1, column=0, sticky="ew")
        photo_row.grid_columnconfigure(0, weight=1)
        photo_entry = ctk.CTkEntry(photo_row, height=42, placeholder_text="Selecionar uma imagem")
        photo_entry.grid(row=0, column=0, padx=(0, 8), sticky="ew")
        photo_entry.insert(0, initial_value)
        self.registration_fields["foto_path"] = photo_entry
        ctk.CTkButton(photo_row, text="Escolher", width=82, height=42, command=lambda: self._choose_photo("foto_path")).grid(row=0, column=1)
        return row + 2

    def show_login(self) -> None:
        form = self._build_shell("Bem-vindo de volta", "Informe seus dados para acessar sua conta.")
        username = self._field(form, 2, "Usuário")
        password = self._field(form, 4, "Senha", password=True)
        password.bind("<Return>", lambda _event: self.login(username.get(), password.get()))
        ctk.CTkButton(form, text="Entrar", height=44, command=lambda: self.login(username.get(), password.get())).grid(row=6, column=0, pady=(24, 15), sticky="ew")
        ctk.CTkButton(form, text="Ainda não tenho uma conta", height=34, fg_color="transparent", text_color=("#3156d9", "#7d9dff"), hover_color=("#e7ebf8", "#293552"), command=self.show_register).grid(row=7, column=0, sticky="ew")
        ctk.CTkButton(form, text="Esqueci minha senha", height=30, fg_color="transparent", text_color=("#65708a", "#abb4c6"), command=self.show_password_reset).grid(row=8, column=0, sticky="ew")
        username.focus()

    def show_register(self) -> None:
        form = self._build_shell("Criar uma conta", "Preencha seus dados. A senha precisa ter 8 caracteres, uma maiúscula e um número. O CEP é buscado automaticamente.")
        self.registration_fields = {}
        fields = [
            ("username", "Usuário", False), ("cpf", "CPF", False),
            ("password", "Senha", True), ("confirm", "Confirmar senha", True),
            ("cep", "CEP", False), ("logradouro", "Logradouro", False),
            ("numero", "Número", False), ("complemento", "Complemento", False),
            ("bairro", "Bairro", False), ("cidade", "Cidade", False), ("uf", "UF", False),
            ("estado_civil", "Estado civil", False), ("cor_pele", "Cor de pele", False),
        ]
        row = 2
        for key, label, password in fields:
            self.registration_fields[key] = self._field(form, row, label, password)
            row += 2
        row = self._add_photo_selector(form, row)
        self.registration_fields["cpf"].bind("<FocusOut>", self._format_cpf)
        self.registration_fields["cep"].bind("<FocusOut>", self._format_cep)
        self.registration_fields["cep"].bind("<Return>", lambda _event: self.search_cep())
        self.cep_status = ctk.CTkLabel(form, text="", font=ctk.CTkFont(size=12), wraplength=300, justify="left")
        self.cep_status.grid(row=row, column=0, pady=(7, 4), sticky="w")
        ctk.CTkButton(form, text="Criar conta", height=44, command=self.register).grid(row=row + 1, column=0, pady=(14, 12), sticky="ew")
        ctk.CTkButton(form, text="Voltar para o login", height=34, fg_color="transparent", text_color=("#3156d9", "#7d9dff"), hover_color=("#e7ebf8", "#293552"), command=self.show_login).grid(row=row + 2, column=0, sticky="ew")
        self.registration_fields["username"].focus()

    def register(self) -> None:
        values = {name: entry.get().strip() for name, entry in self.registration_fields.items()}
        username, password, confirm = values["username"], values["password"], values["confirm"]
        cpf = self._only_digits(values["cpf"])
        cep = self._only_digits(values["cep"])
        if len(username) < 3:
            messagebox.showwarning("Dados incompletos", "O usuário deve ter ao menos 3 caracteres.")
        elif not self._is_valid_cpf(cpf):
            messagebox.showwarning("CPF inválido", "Informe um CPF válido.")
        elif not self._is_strong_password(password):
            messagebox.showwarning("Senha fraca", "Use ao menos 8 caracteres, uma letra maiúscula e um número.")
        elif password != confirm:
            messagebox.showwarning("Senhas diferentes", "A confirmação de senha não confere.")
        elif len(cep) != 8 or not all(values[field] for field in ("logradouro", "numero", "bairro", "cidade", "uf")):
            messagebox.showwarning("Endereço incompleto", "Informe um CEP válido e complete os dados obrigatórios do endereço.")
        else:
            try:
                photo_path = self._store_photo(values["foto_path"])
            except ValueError as error:
                messagebox.showwarning("Foto inválida", str(error))
                return
            if not self.database.create_user(username, password, {
            "cpf": cpf, "cep": cep, "logradouro": values["logradouro"],
            "numero": values["numero"], "complemento": values["complemento"],
            "bairro": values["bairro"], "cidade": values["cidade"], "uf": values["uf"].upper(),
            "foto_path": photo_path, "estado_civil": values["estado_civil"], "cor_pele": values["cor_pele"],
            }):
                messagebox.showerror("Dados já cadastrados", "Este usuário ou CPF já está em uso.")
            else:
                messagebox.showinfo("Conta criada", "Cadastro realizado. Agora você já pode entrar.")
                self.show_login()

    def login(self, username: str, password: str) -> None:
        username = username.strip()
        authenticated, reason = self.database.authenticate(username, password)
        if authenticated:
            self.current_user = username
            self.show_dashboard()
        else:
            messagebox.showerror("Acesso negado", reason)

    def show_dashboard(self) -> None:
        self._clear_screen()
        user = self.database.get_user(self.current_user)
        if user is None:
            self.show_login()
            return
        panel = ctk.CTkScrollableFrame(self, corner_radius=20)
        panel.grid(row=0, column=0, padx=36, pady=36, sticky="nsew")
        panel.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(panel, text="PORTAL", font=ctk.CTkFont(size=15, weight="bold"), text_color=("#3156d9", "#7d9dff")).grid(row=0, column=0, padx=40, pady=(42, 0), sticky="w")
        ctk.CTkLabel(panel, text=f"Olá, {self.current_user}!", font=ctk.CTkFont(size=30, weight="bold")).grid(row=1, column=0, padx=40, pady=(8, 18), sticky="w")
        photo_path = user["foto_path"] or ""
        if photo_path and Path(photo_path).is_file():
            try:
                with Image.open(photo_path) as image_file:
                    image = image_file.copy()
                self.profile_image = ctk.CTkImage(image, size=(120, 120))
                ctk.CTkLabel(panel, text="", image=self.profile_image).grid(row=2, column=0, padx=40, pady=(0, 18), sticky="w")
            except (OSError, ValueError):
                pass
        address = f"{user['logradouro'] or '-'}, {user['numero'] or '-'}"
        if user["complemento"]:
            address += f" — {user['complemento']}"
        profile_items = [
            ("CPF", self._format_cpf_value(user["cpf"])),
            ("Estado civil", user["estado_civil"] or "Não informado"),
            ("Cor de pele", user["cor_pele"] or "Não informada"),
            ("Endereço", address),
            ("Bairro", user["bairro"] or "-"),
            ("Cidade / UF", f"{user['cidade'] or '-'} / {user['uf'] or '-'}"),
            ("CEP", self._format_cep_value(user["cep"])),
        ]
        info = ctk.CTkFrame(panel, corner_radius=14, fg_color=("#edf1fb", "#252d3e"))
        info.grid(row=3, column=0, padx=40, pady=(0, 22), sticky="ew")
        info.grid_columnconfigure(1, weight=1)
        for row, (label, value) in enumerate(profile_items):
            ctk.CTkLabel(info, text=f"{label}:", font=ctk.CTkFont(size=13, weight="bold")).grid(row=row, column=0, padx=(18, 10), pady=7, sticky="nw")
            ctk.CTkLabel(info, text=value, font=ctk.CTkFont(size=13), wraplength=480, justify="left").grid(row=row, column=1, padx=(0, 18), pady=7, sticky="w")
        buttons = ctk.CTkFrame(panel, fg_color="transparent")
        buttons.grid(row=4, column=0, padx=40, pady=(0, 38), sticky="w")
        ctk.CTkButton(buttons, text="Editar informações", command=self.show_edit_profile).grid(row=0, column=0, padx=(0, 10))
        if user["papel"] == "admin":
            ctk.CTkButton(buttons, text="Painel administrativo", command=self.show_admin).grid(row=0, column=1, padx=(0, 10))
        ctk.CTkButton(buttons, text="Alternar tema", width=120, fg_color="transparent", border_width=1, command=self.toggle_theme).grid(row=0, column=2)
        ctk.CTkButton(buttons, text="Sair", width=90, fg_color="transparent", border_width=1, command=self.show_login).grid(row=0, column=3, padx=(10, 0))

    def toggle_theme(self) -> None:
        current = ctk.get_appearance_mode()
        ctk.set_appearance_mode("light" if current == "Dark" else "dark")

    def show_password_reset(self) -> None:
        form = self._build_shell("Redefinir senha", "Confirme usuário e CPF para definir uma nova senha.")
        self.reset_username = self._field(form, 2, "Usuário")
        self.reset_cpf = self._field(form, 4, "CPF")
        self.reset_new_password = self._field(form, 6, "Nova senha", password=True)
        ctk.CTkButton(form, text="Atualizar senha", height=44, command=self.confirm_password_reset).grid(row=8, column=0, pady=(22, 12), sticky="ew")
        ctk.CTkButton(form, text="Voltar", height=34, fg_color="transparent", command=self.show_login).grid(row=9, column=0, sticky="ew")

    def confirm_password_reset(self) -> None:
        password = self.reset_new_password.get()
        if not self._is_strong_password(password):
            messagebox.showwarning("Senha fraca", "Use ao menos 8 caracteres, uma letra maiúscula e um número.")
            return
        if self.database.change_password_with_cpf(self.reset_username.get().strip(), self._only_digits(self.reset_cpf.get()), password):
            messagebox.showinfo("Senha atualizada", "Agora você pode entrar com a nova senha.")
            self.show_login()
        else:
            messagebox.showerror("Dados inválidos", "Usuário e CPF não conferem.")

    def show_admin(self) -> None:
        user = self.database.get_user(self.current_user)
        if user is None or user["papel"] != "admin":
            messagebox.showerror("Sem permissão", "Este painel é exclusivo para administradores.")
            self.show_dashboard()
            return
        self._clear_screen()
        panel = ctk.CTkFrame(self, corner_radius=20)
        panel.grid(row=0, column=0, padx=28, pady=28, sticky="nsew")
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(3, weight=1)
        ctk.CTkLabel(panel, text="Painel administrativo", font=ctk.CTkFont(size=28, weight="bold")).grid(row=0, column=0, padx=28, pady=(26, 8), sticky="w")
        ctk.CTkLabel(panel, text="Pesquise por usuário, CPF ou cidade. Contas podem ser desativadas sem excluir o histórico.", text_color=("#65708a", "#abb4c6")).grid(row=1, column=0, padx=28, sticky="w")
        controls = ctk.CTkFrame(panel, fg_color="transparent")
        controls.grid(row=2, column=0, padx=28, pady=18, sticky="ew")
        controls.grid_columnconfigure(0, weight=1)
        self.admin_search = ctk.CTkEntry(controls, placeholder_text="Buscar usuário, CPF ou cidade")
        self.admin_search.grid(row=0, column=0, padx=(0, 8), sticky="ew")
        self.admin_search.bind("<KeyRelease>", lambda _event: self.refresh_admin_users())
        ctk.CTkButton(controls, text="Exportar CSV", command=self.export_users).grid(row=0, column=1, padx=(0, 8))
        ctk.CTkButton(controls, text="Voltar ao perfil", command=self.show_dashboard).grid(row=0, column=2)
        self.admin_list = ctk.CTkScrollableFrame(panel, corner_radius=12)
        self.admin_list.grid(row=3, column=0, padx=28, pady=(0, 26), sticky="nsew")
        self.admin_list.grid_columnconfigure(1, weight=1)
        self.refresh_admin_users()

    def refresh_admin_users(self) -> None:
        for widget in self.admin_list.winfo_children():
            widget.destroy()
        users = self.database.list_users(self.admin_search.get())
        for index, user in enumerate(users):
            row = ctk.CTkFrame(self.admin_list, corner_radius=8)
            row.grid(row=index, column=0, pady=4, sticky="ew")
            row.grid_columnconfigure(0, weight=1)
            status = "Ativo" if user["ativo"] else "Desativado"
            ctk.CTkLabel(row, text=f"{user['usuario']}  •  {user['cidade'] or '-'} / {user['uf'] or '-'}\n{self._format_cpf_value(user['cpf'])}  •  {user['papel']}  •  {status}", justify="left").grid(row=0, column=0, padx=14, pady=9, sticky="w")
            if user["usuario"] != self.current_user:
                label = "Reativar" if not user["ativo"] else "Desativar"
                ctk.CTkButton(row, text=label, width=92, fg_color="#16a34a" if not user["ativo"] else "#b45309", command=lambda name=user["usuario"], active=not user["ativo"]: self.set_user_active(name, active)).grid(row=0, column=1, padx=10)

    def set_user_active(self, username: str, active: bool) -> None:
        self.database.set_active(username, active)
        self.refresh_admin_users()

    def export_users(self) -> None:
        path = filedialog.asksaveasfilename(title="Exportar usuários", defaultextension=".csv", initialfile="usuarios.csv", filetypes=[("CSV", "*.csv")])
        if path:
            total = self.database.export_csv(path)
            messagebox.showinfo("Exportação concluída", f"{total} usuários foram exportados para CSV.")

    @staticmethod
    def _format_cpf_value(cpf: str | None) -> str:
        digits = re.sub(r"\D", "", cpf or "")
        return f"{digits[:3]}.{digits[3:6]}.{digits[6:9]}-{digits[9:]}" if len(digits) == 11 else "-"

    @staticmethod
    def _format_cep_value(cep: str | None) -> str:
        digits = re.sub(r"\D", "", cep or "")
        return f"{digits[:5]}-{digits[5:]}" if len(digits) == 8 else "-"

    def show_edit_profile(self) -> None:
        user = self.database.get_user(self.current_user)
        if user is None:
            self.show_login()
            return
        form = self._build_shell("Editar informações", "Atualize seu perfil e salve as alterações.")
        self.registration_fields = {}
        editable_fields = [
            ("cpf", "CPF"), ("cep", "CEP"), ("logradouro", "Logradouro"),
            ("numero", "Número"), ("complemento", "Complemento"), ("bairro", "Bairro"),
            ("cidade", "Cidade"), ("uf", "UF"), ("estado_civil", "Estado civil"),
            ("cor_pele", "Cor de pele"),
        ]
        row = 2
        for key, label in editable_fields:
            entry = self._field(form, row, label)
            entry.insert(0, user[key] or "")
            self.registration_fields[key] = entry
            row += 2
        row = self._add_photo_selector(form, row, user["foto_path"] or "")
        self.registration_fields["cpf"].bind("<FocusOut>", self._format_cpf)
        self.registration_fields["cep"].bind("<FocusOut>", self._format_cep)
        self.cep_status = ctk.CTkLabel(form, text="", font=ctk.CTkFont(size=12), wraplength=300, justify="left")
        self.cep_status.grid(row=row, column=0, pady=(7, 4), sticky="w")
        ctk.CTkButton(form, text="Salvar alterações", height=44, command=self.save_profile).grid(row=row + 1, column=0, pady=(14, 12), sticky="ew")
        ctk.CTkButton(form, text="Cancelar", height=34, fg_color="transparent", text_color=("#3156d9", "#7d9dff"), command=self.show_dashboard).grid(row=row + 2, column=0, sticky="ew")

    def save_profile(self) -> None:
        values = {name: entry.get().strip() for name, entry in self.registration_fields.items()}
        cpf, cep = self._only_digits(values["cpf"]), self._only_digits(values["cep"])
        if not self._is_valid_cpf(cpf):
            messagebox.showwarning("CPF inválido", "Informe um CPF válido.")
            return
        if len(cep) != 8 or not all(values[field] for field in ("logradouro", "numero", "bairro", "cidade", "uf")):
            messagebox.showwarning("Endereço incompleto", "Informe um CEP válido e complete os dados obrigatórios do endereço.")
            return
        try:
            photo_path = self._store_photo(values["foto_path"])
        except ValueError as error:
            messagebox.showwarning("Foto inválida", str(error))
            return
        data = {**values, "cpf": cpf, "cep": cep, "uf": values["uf"].upper(), "foto_path": photo_path}
        if not self.database.update_user(self.current_user, data):
            messagebox.showerror("CPF já cadastrado", "Este CPF pertence a outra conta.")
            return
        messagebox.showinfo("Perfil atualizado", "Suas informações foram atualizadas com sucesso.")
        self.show_dashboard()


if __name__ == "__main__":
    ctk.set_appearance_mode("system")
    ctk.set_default_color_theme("blue")
    AuthApp().mainloop()
