import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import psycopg2


ROCKY_HOST = "192.168.56.101"
ROCKY_USER = "kovalenko"
SSH_KEY = "/home/vboxuser/.ssh/lab4_rocky"

RESULTS_DIR = Path("results")
BOM_PATH = RESULTS_DIR / "bom_current.cdx.json"
SCAN_PATH = RESULTS_DIR / "scan_current.json"

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


def make_purl(name: str, version: str, arch: str, distro: str) -> str:
    return (
        f"pkg:rpm/rocky/{quote(name, safe='')}"
        f"@{quote(version, safe='')}"
        f"?arch={quote(arch, safe='')}&distro={quote(distro, safe='')}"
    )


def collect_components() -> tuple[dict, list[dict]]:
    os_release = parse_os_release(run_ssh("cat /etc/os-release"))
    arch = run_ssh("uname -m")
    distro = f"{os_release.get('ID', 'rocky')}-{os_release.get('VERSION_ID', '')}"

    query = r"rpm -qa --queryformat '%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}\n'"
    output = run_ssh(query)

    components = []

    for line in output.splitlines():
        parts = line.split("|")

        if len(parts) != 3:
            continue

        name, version, package_arch = parts
        purl = make_purl(name, version, package_arch, distro)

        components.append(
            {
                "type": "library",
                "bom-ref": purl,
                "name": name,
                "version": version,
                "purl": purl,
                "properties": [
                    {"name": "rpm:arch", "value": package_arch},
                    {"name": "rpm:distro", "value": distro},
                ],
            }
        )

    components.sort(key=lambda item: item["name"].lower())

    os_info = {
        "name": os_release.get("PRETTY_NAME", "Rocky Linux"),
        "version": os_release.get("VERSION_ID", ""),
        "arch": arch,
    }

    return os_info, components


def build_bom() -> dict:
    os_info, components = collect_components()

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "operating-system",
                "name": os_info["name"],
                "version": os_info["version"],
                "properties": [
                    {"name": "os:arch", "value": os_info["arch"]},
                ],
            },
        },
        "components": components,
    }


def run_osv_scan() -> None:
    completed = subprocess.run(
        [
            "./osv-scanner",
            "scan",
            str(BOM_PATH),
            "--format",
            "json",
            "--output-file",
            str(SCAN_PATH),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    print(completed.stdout)

    if completed.returncode not in (0, 1):
        raise RuntimeError("osv-scanner failed")


def normalize_severity(value: str | None) -> str:
    if not value:
        return "unknown"

    value = value.lower()

    if value in {"critical", "high", "medium", "low"}:
        return value

    return "unknown"


def extract_vulnerabilities(scan_data: dict) -> list[dict]:
    found = []

    def walk(obj, package_name=None, package_version=None):
        if isinstance(obj, dict):
            package = obj.get("package")

            if isinstance(package, dict):
                package_name = package.get("name") or package.get("purl") or package_name
                package_version = package.get("version") or package_version

            vulnerabilities = obj.get("vulnerabilities")

            if isinstance(vulnerabilities, list):
                for vuln in vulnerabilities:
                    if not isinstance(vuln, dict):
                        continue

                    severity = (
                        vuln.get("severity")
                        or vuln.get("database_specific", {}).get("severity")
                    )

                    found.append(
                        {
                            "osv_id": vuln.get("id") or vuln.get("name") or "unknown",
                            "severity": normalize_severity(severity),
                            "summary": vuln.get("summary") or "",
                            "details": vuln.get("details") or "",
                            "published": vuln.get("published"),
                            "modified": vuln.get("modified"),
                            "package_name": package_name or "",
                            "package_version": package_version or "",
                        }
                    )

            for value in obj.values():
                walk(value, package_name, package_version)

        elif isinstance(obj, list):
            for item in obj:
                walk(item, package_name, package_version)

    walk(scan_data)
    return found


def save_scan(vulnerabilities: list[dict]) -> int:
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0,
    }

    for vuln in vulnerabilities:
        severity_counts[vuln["severity"]] += 1

    machine_id = run_ssh("cat /etc/machine-id")
    scan_time = datetime.now(timezone.utc)

    with psycopg2.connect(**DB_CONFIG) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO vulnerability_scans (
                    asset_id, scan_time, vulnerabilities_count,
                    critical_count, high_count, medium_count, low_count, unknown_count
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id;
                """,
                (
                    machine_id,
                    scan_time,
                    len(vulnerabilities),
                    severity_counts["critical"],
                    severity_counts["high"],
                    severity_counts["medium"],
                    severity_counts["low"],
                    severity_counts["unknown"],
                ),
            )

            scan_id = cur.fetchone()[0]

            for vuln in vulnerabilities:
                cur.execute(
                    """
                    INSERT INTO vulnerabilities (
                        osv_id, severity, summary, details, published, modified
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (osv_id) DO UPDATE SET
                        severity = EXCLUDED.severity,
                        summary = EXCLUDED.summary,
                        details = EXCLUDED.details,
                        published = EXCLUDED.published,
                        modified = EXCLUDED.modified
                    RETURNING id;
                    """,
                    (
                        vuln["osv_id"],
                        vuln["severity"],
                        vuln["summary"],
                        vuln["details"],
                        vuln["published"],
                        vuln["modified"],
                    ),
                )

                vulnerability_id = cur.fetchone()[0]

                cur.execute(
                    """
                    INSERT INTO package_vulnerabilities (
                        scan_id, package_name, package_version, vulnerability_id
                    )
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT DO NOTHING;
                    """,
                    (
                        scan_id,
                        vuln["package_name"],
                        vuln["package_version"],
                        vulnerability_id,
                    ),
                )

    return scan_id


def main():
    RESULTS_DIR.mkdir(exist_ok=True)

    bom = build_bom()

    with BOM_PATH.open("w", encoding="utf-8") as file:
        json.dump(bom, file, ensure_ascii=False, indent=2)

    print(f"BOM file: {BOM_PATH}")
    print(f"Components: {len(bom['components'])}")

    run_osv_scan()

    scan_data = json.loads(SCAN_PATH.read_text(encoding="utf-8"))
    vulnerabilities = extract_vulnerabilities(scan_data)
    scan_id = save_scan(vulnerabilities)

    result = {
        "scan_id": scan_id,
        "bom_file": str(BOM_PATH),
        "scan_file": str(SCAN_PATH),
        "components": len(bom["components"]),
        "vulnerabilities": len(vulnerabilities),
    }

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
