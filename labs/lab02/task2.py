import argparse
import csv
import json
import logging
import re
import sys
from pathlib import Path

# Створюємо власнальний логер для модуля (усуває помилку LOG015)
logger = logging.getLogger(__name__)

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
]


def analyze_http_headers(json_path: Path) -> dict:
    if not json_path.exists():
        logger.error(f"Файл не знайдено: {json_path}")
        sys.exit(1)

    with open(json_path, mode="r", encoding="utf-8") as f:
        data = json.load(f)

    results = []
    software_leaks = []

    for site in data:
        target = site.get("url", "unknown")
        headers = site.get("headers", {})

        missing = []
        score = 100

        for sec_header in SECURITY_HEADERS:
            if sec_header not in headers:
                missing.append(sec_header)
                score -= 20

        if score >= 90:
            status, grade = "PASS", "A+"
        elif score >= 70:
            status, grade = "PASS", "B"
        elif score >= 60:
            status, grade = "WARN", "C"
        else:
            status, grade = "FAIL", "F"

        score_str = f"{score}/100 ({grade})"
        results.append(
            {
                "target": target,
                "score": score_str,
                "status": status,
                "missing": ", ".join(missing) if missing else "None",
            }
        )

        if "Server" in headers and re.search(r"[\d.]+", headers["Server"]):
            software_leaks.append(
                f"[LEAK] {target} leaks version in 'Server': {headers['Server']}"
            )
        if "X-Powered-By" in headers:
            software_leaks.append(
                f"[LEAK] {target} leaks tech stack in 'X-Powered-By': {headers['X-Powered-By']}"
            )

    return {"results": results, "leaks": software_leaks}


def run_analyzer(
    headers_file: str, output_csv: str | None = None, log_level: str = "INFO"
):
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="[%(levelname)s] %(message)s",
    )
    headers_path = Path(headers_file)

    logger.info(f"Auditing HTTP response headers from {headers_path}...")
    analysis = analyze_http_headers(headers_path)

    print(
        f"\n{'Target Resource Headers':<30} {'Security Score':<15} {'Status':<8} {'Missing Security'}"
    )
    print("-" * 80)
    for row in analysis["results"]:
        print(
            f"{row['target']:<30} {row['score']:<15} {row['status']:<8} {row['missing']}"
        )

    print("\n=== Server Software Leak Alerts ===")
    for leak in analysis["leaks"]:
        print(leak)

    if output_csv:
        out_path = Path(output_csv)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=["target", "score", "status", "missing"]
            )
            writer.writeheader()
            writer.writerows(analysis["results"])
        logger.info(f"Header audit report generated at {out_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Auditor of HTTP response security headers."
    )
    parser.add_argument(
        "--headers-file",
        required=True,
        help="Path to JSON file with HTTP headers",
    )
    parser.add_argument("--output-csv", help="Path to export CSV report")
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level (DEBUG, INFO, WARNING, ERROR)",
    )

    args = parser.parse_args()
    run_analyzer(args.headers_file, args.output_csv, args.log_level)


if __name__ == "__main__":
    main()
