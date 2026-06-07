import json
import socket
import subprocess
from datetime import datetime, timezone

import psycopg2


ROCKY_HOST = "192.168.56.101"
ROCKY_USER = "kovalenko"
SSH_KEY = "/home/vboxuser/.ssh/lab4_rocky"

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "lab4",
    "user": "lab4",
    "password": "lab4",
}


def run_ssh(command: str) -> str:
    completed = subprocess.run(
        [
            "ssh",
            "-i",
            SSH_KEY,
            "-o",
            "StrictHostKeyChecking=no",
            f"{ROCKY_USER}@{ROCKY_HOST}",
            command,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def parse_os_release(text: str) -> dict:
    result = {}

    for line in text.splitlines():
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        result[key] = value.strip().strip('"')

    return result


def collect_os_info() -> dict:
    os_release = parse_os_release(run_ssh("cat /etc/os-release"))
    arch = run_ssh("uname -m")
    machine_id = run_ssh("cat /etc/machine-id")
    hostname = run_ssh("hostname")

    return {
        "asset_id": machine_id,
        "hostname": hostname,
        "os_name": os_release.get("NAME", ""),
        "os_version": os_release.get("VERSION", ""),
        "os_arch": arch,
        "os_id": os_release.get("ID", ""),
        "version_id": os_release.get("VERSION_ID", ""),
        "description": os_release.get("PRETTY_NAME", ""),
    }


def collect_packages() -> list[dict]:
    query = r"rpm -qa --queryformat '%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}|%{SUMMARY}|%{SIZE}\n'"
    output = run_ssh(query)

    packages = []

    for line in output.splitlines():
        parts = line.split("|", 4)

        if len(parts) != 5:
            continue

        name, version, arch, description, size = parts

        purl = f"pkg:rpm/rocky/{name}@{version}?arch={arch}"

        packages.append(
            {
                "name": name,
                "version": version,
                "arch": arch,
                "description": description,
                "purl": purl,
            }
        )

    return packages


def save_inventory(os_info: dict, packages: list[dict]) -> int:
    scan_time = datetime.now(timezone.utc)

    with psycopg2.connect(**DB_CONFIG) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO assets (
                    asset_id, hostname, os_name, os_version, os_arch,
                    os_id, version_id, description
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (asset_id) DO UPDATE SET
                    hostname = EXCLUDED.hostname,
                    os_name = EXCLUDED.os_name,
                    os_version = EXCLUDED.os_version,
                    os_arch = EXCLUDED.os_arch,
                    os_id = EXCLUDED.os_id,
                    version_id = EXCLUDED.version_id,
                    description = EXCLUDED.description;
                """,
                (
                    os_info["asset_id"],
                    os_info["hostname"],
                    os_info["os_name"],
                    os_info["os_version"],
                    os_info["os_arch"],
                    os_info["os_id"],
                    os_info["version_id"],
                    os_info["description"],
                ),
            )

            cur.execute(
                """
                INSERT INTO inventory_scans (asset_id, scan_time, package_count)
                VALUES (%s, %s, %s)
                RETURNING id;
                """,
                (os_info["asset_id"], scan_time, len(packages)),
            )

            scan_id = cur.fetchone()[0]

            for package in packages:
                cur.execute(
                    """
                    INSERT INTO packages (name, version, arch, description, purl)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (name, version, arch) DO UPDATE SET
                        description = EXCLUDED.description,
                        purl = EXCLUDED.purl
                    RETURNING id;
                    """,
                    (
                        package["name"],
                        package["version"],
                        package["arch"],
                        package["description"],
                        package["purl"],
                    ),
                )

                package_id = cur.fetchone()[0]

                cur.execute(
                    """
                    INSERT INTO installed_packages (scan_id, package_id)
                    VALUES (%s, %s)
                    ON CONFLICT DO NOTHING;
                    """,
                    (scan_id, package_id),
                )

    return scan_id


def main():
    os_info = collect_os_info()
    packages = collect_packages()
    scan_id = save_inventory(os_info, packages)

    result = {
        "scan_id": scan_id,
        "asset_id": os_info["asset_id"],
        "hostname": os_info["hostname"],
        "os": os_info["description"],
        "package_count": len(packages),
    }

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
