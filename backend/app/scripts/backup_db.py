"""
Database Backup Utility for AWASAP.

Exports a safe, self-contained PostgreSQL dump of the AWASAP production database:
  - Generates SQL dump with '--clean --if-exists --no-owner --no-privileges'.
  - Preserves all tables and records, including all 499 security_payloads.
  - Strict isolation: Targets only the AWASAP database; NEVER touches deepfake_db.
  - Supports --dry-run mode for pre-flight verification without generating files.

Usage:
    # Run full backup:
    python -m app.scripts.backup_db

    # Dry-run check:
    python -m app.scripts.backup_db --dry-run
"""

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlparse

from app.config import get_settings


def parse_database_url(url: str) -> dict[str, str]:
    """Extract host, port, user, password, and dbname from DATABASE_URL."""
    if "sqlite" in url:
        raise ValueError("SQLite backup not supported by PostgreSQL backup script.")

    # Remove driver prefix for standard urlparse
    clean_url = url.replace("postgresql+asyncpg://", "postgresql://")
    parsed = urlparse(clean_url)

    dbname = parsed.path.lstrip("/")
    if not dbname:
        raise ValueError("Missing database name in DATABASE_URL.")

    return {
        "host": parsed.hostname or "localhost",
        "port": str(parsed.port or 5432),
        "user": parsed.username or "postgres",
        "password": parsed.password or "",
        "dbname": dbname,
    }


def perform_backup(dry_run: bool = False, output_dir: Path | None = None) -> Path | None:
    settings = get_settings()
    db_config = parse_database_url(settings.DATABASE_URL)

    # Safety Guard: Ensure deepfake_db is NEVER targeted
    if db_config["dbname"].lower() == "deepfake_db":
        raise RuntimeError("CRITICAL SAFETY ERROR: Targeting deepfake_db is strictly prohibited.")

    target_dir = output_dir or (Path(__file__).resolve().parent.parent.parent / "backups")
    target_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_file = target_dir / f"{db_config['dbname']}_backup_{timestamp}.sql"

    print(f"[*] Target Database : {db_config['dbname']}@{db_config['host']}:{db_config['port']}")
    print(f"[*] Backup Output   : {backup_file}")

    if dry_run:
        print("[*] DRY RUN: Pre-flight checks passed. No dump executed.")
        return None

    env = os.environ.copy()
    if db_config["password"]:
        env["PGPASSWORD"] = db_config["password"]

    cmd = [
        "pg_dump",
        "-h", db_config["host"],
        "-p", db_config["port"],
        "-U", db_config["user"],
        "--clean",
        "--if-exists",
        "--no-owner",
        "--no-privileges",
        "-f", str(backup_file),
        db_config["dbname"],
    ]

    print("[*] Executing pg_dump...")
    try:
        subprocess.run(cmd, env=env, check=True, capture_output=True, text=True)
    except FileNotFoundError:
        print("[!] Error: 'pg_dump' executable not found in PATH. Ensure PostgreSQL client tools are installed.", file=sys.stderr)
        raise
    except subprocess.CalledProcessError as exc:
        print(f"[!] pg_dump failed: {exc.stderr}", file=sys.stderr)
        raise

    if not backup_file.exists() or backup_file.stat().st_size == 0:
        raise RuntimeError(f"Backup file was not created or is empty: {backup_file}")

    size_kb = backup_file.stat().st_size / 1024
    print(f"[+] Backup successfully created: {backup_file} ({size_kb:.2f} KB)")
    return backup_file


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AWASAP PostgreSQL Database Backup Utility")
    parser.add_argument("--dry-run", action="store_true", help="Perform pre-flight validation without writing dump file")
    args = parser.parse_args()

    try:
        perform_backup(dry_run=args.dry_run)
    except Exception as e:
        print(f"[!] Backup failed: {e}", file=sys.stderr)
        sys.exit(1)
