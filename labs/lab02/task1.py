import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

SESSION_TIMEOUT_SEC = 900


class User:
    def __init__(self, username: str, email: str, role: str = "user"):
        self.username = username
        self.email = email
        self.role = role
        self.active = True
        self.__password_salt: bytes = os.urandom(16)
        self.__password_hash: bytes = b""

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str):
        pattern = r"^[a-zA-Z][a-zA-Z0-9._%+-]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, value):
            raise ValueError(f"Некоректний формат email: {value}")
        self._email = value

    def set_password(self, password: str) -> None:
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, 100_000
        )

    def check_password(self, password: str) -> bool:
        if not self.__password_hash:
            return False
        new_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, 100_000
        )
        return hmac.compare_digest(self.__password_hash, new_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        status = "Active" if self.active else "Inactive"
        return f"User({self.username}, Email: {self.email}, Role: {self.role}, Status: {status})"


class Admin(User):
    def __init__(
        self,
        username: str,
        email: str,
        permissions: list[str] | set[str] | None = None,
    ):
        super().__init__(username, email, role="admin")
        self.permissions: set[str] = set(permissions) if permissions else set()

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        base_str = super().__str__()
        perms = ", ".join(sorted(self.permissions)) if self.permissions else "None"
        return f"{base_str} | Permissions: [{perms}]"


class Session:
    def __init__(self, ip: str):
        self.ip = ip
        now = datetime.now(UTC)
        self.login_time = now
        self.last_activity = now

    def touch(self) -> None:
        self.last_activity = datetime.now(UTC)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("Таймаут має бути позитивним числом.")
        now = datetime.now(UTC)
        return (now - self.last_activity) < timedelta(seconds=timeout_sec)


@dataclass
class AuditEntry:
    timestamp: datetime
    username: str
    action: str


class AuditLog:
    def __init__(self):
        self.entries: list[AuditEntry] = []

    def add_log(self, username: str, action: str) -> None:
        entry = AuditEntry(
            timestamp=datetime.now(UTC),
            username=username,
            action=action,
        )
        self.entries.append(entry)

    def show_all(self) -> list[str]:
        return [
            f"[{e.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}] {e.username} -> {e.action}"
            for e in self.entries
        ]


class UserAccount:
    def __init__(self, user: User, audit_log: AuditLog | None = None):
        self.user = user
        self.session: Session | None = None
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        if not self.user.active or self.user.username != username:
            self.audit_log.add_log(username, "login_failure")
            return False

        if self.user.check_password(password):
            self.session = Session(ip)
            self.session.touch()
            self.audit_log.add_log(username, "login_success")
            return True

        self.audit_log.add_log(username, "login_failure")
        return False

    def is_authenticated(self) -> bool:
        if self.session is None:
            return False
        return self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        if self.session:
            self.audit_log.add_log(self.user.username, "logout")
            self.session = None

    def __getitem__(self, item: str):
        allowed_attrs = {
            "user",
            "session",
            "audit_log",
            "username",
            "email",
            "role",
            "active",
        }
        if item not in allowed_attrs:
            raise KeyError(f"Ключ '{item}' недоступний.")
        if hasattr(self.user, item):
            return getattr(self.user, item)
        return getattr(self, item)

    def __setitem__(self, key: str, value):
        allowed_setters = {"email", "active", "role"}
        if key not in allowed_setters:
            raise KeyError(f"Зміна атрибута '{key}' заборонена через доступ за ключем.")
        setattr(self.user, key, value)
