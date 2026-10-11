import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)

if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

users = {
    "cloud_architect": {
        "role": "cloud_security",
        "clearance": 4,
        "department": "Cloud",
        "active": True,
    },
    "devops_engineer": {
        "role": "devops",
        "clearance": 3,
        "department": "DevOps",
        "active": True,
    },
    "qa_tester": {
        "role": "quality_assurance",
        "clearance": 2,
        "department": "QA",
        "active": True,
    },
    "partner_access": {
        "role": "partner",
        "clearance": 2,
        "department": "Partnership",
        "active": True,
    },
    "migrated_user": {
        "role": "migrated",
        "clearance": 1,
        "department": "Migration",
        "active": False,
    },
}

resources = [
    ("cloud_configs", 4),
    ("deployment_pipelines", 3),
    ("test_environments", 2),
    ("partner_apis", 2),
    ("infrastructure_code", 4),
    ("shared_resources", 1),
    ("container_registry", 3),
    ("secrets_vault", 4),
    ("build_artifacts", 2),
    ("public_endpoints", 1),
]

security_levels = (
    "Development",
    "Staging",
    "Production",
    "Critical Infrastructure",
)

blocked_users = {"migrated_user", "container_breach", "pipeline_compromise"}


def check_access(username: str, resource_name: str, resource_level: int) -> tuple:
    if username not in users:
        return False, "User not found"

    if username in blocked_users:
        return False, "User is blocked"

    user_info = users[username]

    if not user_info.get("active", False):
        return False, "Account inactive"

    user_clearance = user_info.get("clearance", 0)
    if user_clearance >= resource_level:
        return True, ""
    else:
        return False, "Insufficient clearance"


def run_task2():
    print("=" * 70)
    print(
        f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}"
    )
    print("Завдання 2: Багаторівнева система контролю доступу")
    print("=" * 70)

    print("\n--- СПИСОК РЕСУРСІВ СИСТЕМИ ---")
    for res_name, res_level in resources:
        level_label = security_levels[res_level - 1]
        print(f"Ресурс: {res_name:<25} | Рівень безпеки: {level_label}")

    print("\n" + "=" * 70)
    print("--- РЕЗУЛЬТАТИ ПЕРЕВІРКИ ДОСТУПУ ---")
    print("=" * 70)

    test_users = list(users.keys()) + ["container_breach", "unknown_user"]

    for username in test_users:
        for res_name, res_level in resources:
            allowed, reason = check_access(username, res_name, res_level)
            status = "ALLOW" if allowed else "DENY"
            reason_str = f" ({reason})" if reason else ""
            print(
                f"user=[{username:<16}] resource=[{res_name:<21}] -> {status}{reason_str}"
            )


if __name__ == "__main__":
    run_task2()