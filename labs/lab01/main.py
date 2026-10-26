import importlib
import os
import sys

sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def main():
    print("=" * 70)
    print(f"ЛАБОРАТОРНА РОБОТА №1 | Студент: {STUDENT_NAME}")
    print(f"Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 70)

    print("\n>>> ЗАПУСК ЗАВДАННЯ 1: Аналіз паролів")
    importlib.import_module("PSM1")

    print("\n>>> ЗАПУСК ЗАВДАННЯ 2: Контроль доступу")
    importlib.import_module("PSM1 2")

    print("\n>>> ЗАПУСК ЗАВДАННЯ 3: Хешування та логування")
    importlib.import_module("PSM1 3")


if __name__ == "__main__":
    main()
