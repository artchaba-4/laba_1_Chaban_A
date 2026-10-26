import csv
import functools
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)

if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


class ValidationError(Exception):
    pass


HASH_ALGORITHM = "sha224"
MIN_PASSWORD_LENGTH = 13

SALT = str(VARIANT_NUMBER).zfill(5)

DATA_DIR = Path(__file__).resolve().parent / "data"
CSV_FILE_PATH = DATA_DIR / "users.csv"
JSON_LOG_PATH = DATA_DIR / "log.json"

users_to_register = (
    ("cloud_admin", "SecurePass1234!"),
    ("devops_user", "MyDevOpsPass2023#"),
    ("qa_tester1", "TestingPass999!"),
    ("partner_api", "PartnerAccess#888"),
    ("migrated_usr", "OldPassword123!"),
    ("security_lead", "CyberSecurity#2023"),
    ("sys_analyst", "AnalysisPassword!1"),
    ("network_spec", "NetWorkPass321#"),
    ("database_admin", "DBAdminPassword!"),
    ("audit_officer", "AuditSecurePass#1"),
)


def generate_hash(password: str, salt: str = "00000") -> str:
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Довжина пароля має бути не менше {MIN_PASSWORD_LENGTH} символів."
        )

    combined = password + salt
    hasher = hashlib.new(HASH_ALGORITHM)
    hasher.update(combined.encode("utf-8"))
    return hasher.hexdigest()


def create_user(username: str, password: str) -> tuple:
    hash_val = generate_hash(password, SALT)
    return (username, hash_val)


def create_users(users_list: tuple):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    records = []
    for uname, pwd in users_list:
        try:
            user_record = create_user(uname, pwd)
            records.append(user_record)
        except (ValueError, ValidationError) as e:
            print(f"[ПОМИЛКА РЕЄСТРАЦІЇ] Для {uname}: {e}")

    with open(CSV_FILE_PATH, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["username", "password_hash"])
        writer.writerows(records)


def load_users_db() -> list:
    users_db = []
    if not CSV_FILE_PATH.exists():
        raise FileNotFoundError(f"Файл бази даних {CSV_FILE_PATH} не знайдено.")

    with open(CSV_FILE_PATH, mode="r", encoding="utf-8") as file:
        reader = csv.reader(file)
        next(reader, None)
        for row in reader:
            if row:
                users_db.append(row)
    return users_db


def log_event(func):
    @functools.wraps(func)
    def wrapper(username: str, password: str, *args, **kwargs):
        result_status = "failure"
        try:
            res = func(username, password, *args, **kwargs)
            if res:
                result_status = "success"
            return res
        except Exception:
            result_status = "failure"
            raise
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "args": list(args),
                "kwargs": kwargs,
            }

            logs = []
            if JSON_LOG_PATH.exists():
                try:
                    with open(JSON_LOG_PATH, mode="r", encoding="utf-8") as f:
                        logs = json.load(f)
                except (OSError, json.JSONDecodeError):
                    logs = []

            logs.append(log_entry)

            with open(JSON_LOG_PATH, mode="w", encoding="utf-8") as f:
                json.dump(logs, f, indent=4, ensure_ascii=False)

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Логін та пароль не можуть бути порожніми!")

    users_db = load_users_db()

    try:
        input_hash = generate_hash(password, SALT)
    except (ValidationError, ValueError):
        return False

    for db_user, db_hash in users_db:
        if db_user == username and db_hash == input_hash:
            return True

    return False


def run_task3():
    print(">>> ЗАПУСК ЗАВДАННЯ 3: Хешування, CSV та JSON-логування")
    print("=" * 70)
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 70)
    print(f"Параметри: Хеш = {HASH_ALGORITHM} | Сіль = '{SALT}'\n")

    print("1. Реєстрація користувачів та збереження у CSV...")
    create_users(users_to_register)

    print("\n2. Зчитування бази даних з CSV:")
    db = load_users_db()
    print("=" * 80)
    print(f"{'Користувач':<20} | {f'Хеш пароля ({HASH_ALGORITHM.upper()})':<55}")
    print("=" * 80)
    for uname, hval in db:
        print(f"{uname:<20} | {hval}")
    print("=" * 80)

    print("\n3. Тестування автентифікації (з автоматичним логуванням у JSON):")
    res1 = login("cloud_admin", "SecurePass1234!")
    print(f"Вхід cloud_admin: {'УСПІШНО' if res1 else 'НЕВДАЛО'}")

    res2 = login("cloud_admin", "WrongPassword123!")
    print(f"Вхід cloud_admin (невірний пароль): {'УСПІШНО' if res2 else 'НЕВДАЛО'}")

    res3 = login("hacker_unknown", "some_password")
    print(f"Вхід hacker_unknown: {'УСПІШНО' if res3 else 'НЕВДАЛО'}")

    print("\n4. Перевірка обробки винятків (порожній логін):")
    try:
        login("", "")
    except ValueError as e:
        print(f"[СПІЙМАНО ВИНОТОК] ValueError: {e}")


if __name__ == "__main__":
    run_task3()
