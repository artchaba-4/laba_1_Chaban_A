import os
import random
import sys

# --- ДАНІ БЕРУТЬСЯ ВИКЛЮЧНО З ПАПКИ SHARED ---
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)

if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Вхідні дані
passwords = [
    "Digital@F0r3nsics",
    "plain",
    "Encrypt10n@Key",
    "member",
    "Security@Audit2023",
    "regular",
    "Hack3r@D3fense",
    "ordinary",
    "Threat@Intel",
    "usual",
]

criteria = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

forbidden_passwords = {"plain", "member", "regular", "ordinary", "usual", "user"}


def evaluate_password(
    pwd: str, all_passwords: list, min_len: int, forbid_set: set
) -> str:
    if pwd in forbid_set or len(pwd) < min_len:
        return "Заборонений"

    has_digit = any(c.isdigit() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_lower = any(c.islower() for c in pwd)
    has_special = any(not c.isalnum() for c in pwd)

    meets_all = has_digit and has_upper and has_lower and has_special
    meets_at_least_one = has_digit or has_upper or has_lower or has_special

    if not meets_all:
        return "Слабкий" if meets_at_least_one else "Заборонений"

    if meets_all:
        if len(pwd) >= min_len + 4 and all_passwords.count(pwd) == 1:
            return "Дуже сильний"
        return "Сильний"

    return "Слабкий"


def run_task1():
    print("=" * 65)
    print(
        f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}"
    )
    print("Завдання 1: Комплексний аналізатор надійності паролів")
    print("=" * 65)

    working_passwords = passwords.copy()
    random_indices = random.sample(range(len(working_passwords)), 3)
    duplicates = [working_passwords[i] for i in random_indices]
    working_passwords.extend(duplicates)

    print(f"Додано дублікати для паролів: {duplicates}\n")
    print(f"{'№':<3} | {'Пароль':<22} | {'Довжина':<8} | {'Категорія'}")
    print("-" * 65)

    min_len = criteria["min_length"]

    for idx, pwd in enumerate(working_passwords, start=1):
        category = evaluate_password(
            pwd, working_passwords, min_len, forbidden_passwords
        )
        print(f"{idx:<3} | {pwd:<22} | {len(pwd):<8} | {category}")

    print("-" * 65)


if __name__ == "__main__":
    run_task1()