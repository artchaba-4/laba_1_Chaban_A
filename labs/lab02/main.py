import sys

from labs.lab02.task1 import Admin, AuditLog, User, UserAccount
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def run_demo():
    print("=" * 70)
    print(f"ЛАБОРАТОРНА РОБОТА №2 | Студент: {STUDENT_NAME}")
    print(f"Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 70)

    print("\n>>> 1. Створення користувача та Admin...")
    user = User("vlad_user", "vlad.user@example.com")
    user.set_password("SecurePassword123!")

    admin = Admin("vlad_admin", "admin.vlad@corp.com", permissions={"read", "write"})
    admin.grant_permission("delete")
    print(user)
    print(admin)

    print("\n>>> 2. Тестування валідації email (@property)...")
    try:
        user.email = "bad_email"
    except ValueError as e:
        print(f"[СПІЙМАНО ВИНЯТОК]: {e}")

    print("\n>>> 3. Демонстрація UserAccount, автентифікації та аудиту...")
    audit = AuditLog()
    account = UserAccount(user, audit)

    print("Спроба входу з НЕВІРНИМ паролем:")
    account.login("vlad_user", "WrongPass", "192.168.1.10")
    print(f"Статус автентифікації: {account.is_authenticated()}")

    print("Спроба входу з ПРАВИЛЬНИМ паролем:")
    account.login("vlad_user", "SecurePassword123!", "192.168.1.10")
    print(f"Статус автентифікації: {account.is_authenticated()}")

    print("\nПеревірка доступу за ключем (__getitem__):")
    print(f"account['username'] -> {account['username']}")
    print(f"account['email'] -> {account['email']}")

    print("\n>>> 4. Завершення сесії та журнал аудиту:")
    account.logout()

    print("\nЗаписи AuditLog:")
    for log_line in audit.show_all():
        print(log_line)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        run_demo()
    elif len(sys.argv) > 1 and sys.argv[1] == "analyze":
        sys.argv.pop(1)
        from labs.lab02.task2 import main as task2_main

        task2_main()
    else:
        print("Використання:")
        print("  python -m labs.lab02.main demo")
        print(
            "  python -m labs.lab02.main analyze --headers-file labs/lab02/data/http_headers.json"
        )


if __name__ == "__main__":
    main()
