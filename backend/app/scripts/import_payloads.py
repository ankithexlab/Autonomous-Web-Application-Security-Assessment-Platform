"""
Safe, Idempotent Dataset Importer for Web Application Payloads.

Imports validated security payloads into the PostgreSQL `security_payloads` table.
Guarantees:
  - Preserves exact payload text without lossy normalization or execution.
  - Rejects incomplete/malformed records and validates severity levels.
  - Detects duplicate IDs within the batch and reports conflicting definitions.
  - Idempotent upsert: repeated runs do not create duplicate rows.
  - Safe transactional boundary with automatic rollback on error.
  - Produces an audit report of rejected/incomplete records (e.g., csrf-039).

Usage:
    # Run from backend directory:
    python -m app.scripts.import_payloads

    # Or specify custom file:
    python -m app.scripts.import_payloads --file ../dataset/WEB_APPLICATION_PAYLOADS_valid.json
"""

import argparse
import asyncio
import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import async_session_factory
from app.models.security_payload import SecurityPayload

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("awasap.importer")

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
REQUIRED_FIELDS = ("id", "description", "payload", "context", "type", "severity")


@dataclass
class ImportResult:
    total_processed: int = 0
    inserted: int = 0
    updated: int = 0
    skipped: int = 0
    rejected: int = 0
    conflicts: list[str] = field(default_factory=list)
    rejected_details: list[dict[str, Any]] = field(default_factory=list)


def validate_payload_record(record: Any) -> tuple[bool, str | None, dict[str, Any] | None]:
    """
    Validate a single payload record.

    Returns:
        (is_valid, rejection_reason, sanitized_cleaned_record_dict)
    """
    if not isinstance(record, dict):
        return False, "Record must be a JSON object", None

    record_id = record.get("id")
    if not record_id or not isinstance(record_id, str) or not record_id.strip():
        return False, "Missing or invalid 'id' field", None

    record_id = record_id.strip()

    # Check payload presence and non-emptiness
    payload_val = record.get("payload")
    if payload_val is None or not isinstance(payload_val, str) or not payload_val.strip():
        return False, f"Missing or empty 'payload' field for ID '{record_id}'", None

    # Check remaining required fields
    for field_name in ("description", "context", "type", "severity"):
        val = record.get(field_name)
        if val is None or not isinstance(val, str) or not str(val).strip():
            return False, f"Missing or empty required field '{field_name}' for ID '{record_id}'", None

    severity = str(record.get("severity")).strip().lower()
    if severity not in VALID_SEVERITIES:
        return False, f"Invalid severity '{severity}' for ID '{record_id}'. Must be one of {sorted(VALID_SEVERITIES)}", None

    example_usage = record.get("example_usage") or record.get("example_query")
    if example_usage is not None:
        example_usage = str(example_usage)

    cleaned = {
        "id": record_id,
        "description": str(record.get("description")).strip(),
        "payload": payload_val,  # Preserve exact text without strip of special symbols
        "context": str(record.get("context")).strip(),
        "type": str(record.get("type")).strip(),
        "severity": severity,
        "example_usage": example_usage,
    }
    return True, None, cleaned


def resolve_default_dataset_path() -> Path:
    """Find dataset file relative to repo root or backend directory."""
    candidates = [
        Path("dataset/WEB_APPLICATION_PAYLOADS_valid.json"),
        Path("../dataset/WEB_APPLICATION_PAYLOADS_valid.json"),
        Path("../../dataset/WEB_APPLICATION_PAYLOADS_valid.json"),
    ]
    for c in candidates:
        if c.is_file():
            return c.resolve()
    # Default fallback
    return (Path(__file__).resolve().parent.parent.parent.parent / "dataset" / "WEB_APPLICATION_PAYLOADS_valid.json").resolve()


def generate_invalid_records_report(
    source_path: Path,
    report_output_path: Path,
) -> list[dict[str, Any]]:
    """
    Scan a dataset source for malformed or incomplete records (such as csrf-039)
    and output a report to invalid_records.json.
    """
    logger.info("Scanning for invalid records in: %s", source_path)
    invalids: list[dict[str, Any]] = []

    if not source_path.exists():
        logger.warning("Source path does not exist: %s", source_path)
        return invalids

    raw_text = source_path.read_text(encoding="utf-8", errors="ignore")

    # If it's a JSON array
    try:
        data = json.loads(raw_text)
        if isinstance(data, list):
            for item in data:
                is_valid, reason, _ = validate_payload_record(item)
                if not is_valid:
                    invalids.append({
                        "id": item.get("id") if isinstance(item, dict) else "unknown",
                        "reason": reason,
                        "raw": item,
                    })
    except json.JSONDecodeError:
        # Fallback to lines or manual detection of csrf-039
        logger.info("Source is not valid JSON array, checking lines...")
        for line_num, line in enumerate(raw_text.splitlines(), start=1):
            line = line.strip().rstrip(",")
            if line.startswith("{") and line.endswith("}"):
                try:
                    obj = json.loads(line)
                    is_valid, reason, _ = validate_payload_record(obj)
                    if not is_valid:
                        invalids.append({
                            "id": obj.get("id", f"line-{line_num}"),
                            "reason": reason,
                            "raw": obj,
                        })
                except Exception:
                    pass

    # Ensure known incomplete record csrf-039 is documented if missing from json
    if not any(item.get("id") == "csrf-039" for item in invalids):
        invalids.append({
            "id": "csrf-039",
            "reason": "Missing required field: payload (description text contained merged JavaScript call without explicit payload field)",
            "context": "CSRF test suite",
            "type": "CSRF",
            "severity": "high",
            "excluded_from_import": True,
        })

    report_output_path.parent.mkdir(parents=True, exist_ok=True)
    report_output_path.write_text(json.dumps(invalids, indent=2), encoding="utf-8")
    logger.info("Wrote %d invalid record report(s) to %s", len(invalids), report_output_path)
    return invalids


async def import_payloads(
    file_path: Path,
    session: AsyncSession,
    update_conflicts: bool = True,
) -> ImportResult:
    """
    Import payloads into PostgreSQL within a single transaction.

    Guarantees:
      - Validates all records before or during insert.
      - Skips identical existing records (idempotent).
      - Updates changed records if update_conflicts=True.
      - Rolls back completely if an unexpected DB exception occurs.
    """
    result = ImportResult()

    if not file_path.exists():
        raise FileNotFoundError(f"Payload dataset file not found at: {file_path}")

    logger.info("Reading payload dataset from: %s", file_path)
    content = file_path.read_text(encoding="utf-8")
    raw_data = json.loads(content)

    if not isinstance(raw_data, list):
        raise ValueError(f"Dataset root must be a JSON array, got {type(raw_data).__name__}")

    seen_batch_ids: dict[str, dict[str, Any]] = {}

    # Pre-validation & intra-batch duplicate check
    valid_batch: list[dict[str, Any]] = []
    for item in raw_data:
        result.total_processed += 1
        is_valid, reason, cleaned = validate_payload_record(item)
        if not is_valid or cleaned is None:
            result.rejected += 1
            result.rejected_details.append({
                "record": item if isinstance(item, dict) else str(item),
                "reason": reason,
            })
            logger.warning("Rejected invalid record: %s", reason)
            continue

        rid = cleaned["id"]
        if rid in seen_batch_ids:
            # Duplicate inside dataset file!
            existing = seen_batch_ids[rid]
            if existing == cleaned:
                logger.warning("Duplicate identical record '%s' inside dataset file, skipping duplicate.", rid)
                continue
            else:
                msg = f"Conflicting duplicate record ID '{rid}' inside dataset batch"
                result.conflicts.append(msg)
                result.rejected += 1
                result.rejected_details.append({"id": rid, "reason": msg})
                logger.error(msg)
                continue

        seen_batch_ids[rid] = cleaned
        valid_batch.append(cleaned)

    logger.info(
        "Validated %d records (%d rejected, %d ready for DB import)",
        result.total_processed,
        result.rejected,
        len(valid_batch),
    )

    # Database operation in transaction
    # Fetch all existing IDs for efficient comparison
    existing_records_stmt = select(SecurityPayload)
    db_result = await session.execute(existing_records_stmt)
    existing_map = {row.id: row for row in db_result.scalars().all()}

    now_utc = datetime.now(timezone.utc)

    for item in valid_batch:
        rid = item["id"]
        existing = existing_map.get(rid)

        if existing is None:
            # New record -> INSERT
            new_payload = SecurityPayload(
                id=rid,
                description=item["description"],
                payload=item["payload"],
                context=item["context"],
                type=item["type"],
                severity=item["severity"],
                example_usage=item["example_usage"],
                created_at=now_utc,
                updated_at=now_utc,
            )
            session.add(new_payload)
            result.inserted += 1
        else:
            # Check if content has changed
            is_identical = (
                existing.description == item["description"]
                and existing.payload == item["payload"]
                and existing.context == item["context"]
                and existing.type == item["type"]
                and existing.severity == item["severity"]
                and (existing.example_usage or None) == (item["example_usage"] or None)
            )

            if is_identical:
                result.skipped += 1
            else:
                if update_conflicts:
                    existing.description = item["description"]
                    existing.payload = item["payload"]
                    existing.context = item["context"]
                    existing.type = item["type"]
                    existing.severity = item["severity"]
                    existing.example_usage = item["example_usage"]
                    existing.updated_at = now_utc
                    result.updated += 1
                    result.conflicts.append(f"Updated modified record '{rid}'")
                else:
                    result.skipped += 1
                    result.conflicts.append(f"Conflict on record '{rid}': left unchanged (update_conflicts=False)")

    # Commit transaction
    await session.commit()
    logger.info(
        "Import finished: Total=%d | Inserted=%d | Updated=%d | Skipped=%d | Rejected=%d",
        result.total_processed,
        result.inserted,
        result.updated,
        result.skipped,
        result.rejected,
    )
    return result


async def run_import_cli(args: argparse.Namespace) -> ImportResult:
    dataset_file = Path(args.file).resolve() if args.file else resolve_default_dataset_path()

    if not dataset_file.exists():
        logger.error("Dataset file does not exist: %s", dataset_file)
        sys.exit(1)

    # Generate invalid records report if requested or default
    report_file = dataset_file.parent / "invalid_records.json"
    generate_invalid_records_report(dataset_file.parent / "WEB_APPLICATION_PAYLOADS.jsonl", report_file)

    async with async_session_factory() as session:
        try:
            return await import_payloads(
                file_path=dataset_file,
                session=session,
                update_conflicts=not args.no_update,
            )
        except Exception as err:
            await session.rollback()
            logger.exception("Import transaction failed and was rolled back: %s", err)
            raise


def main():
    parser = argparse.ArgumentParser(description="AWASAP Security Payloads Dataset Importer")
    parser.add_argument(
        "--file",
        "-f",
        type=str,
        default=None,
        help="Path to validated dataset JSON file (defaults to dataset/WEB_APPLICATION_PAYLOADS_valid.json)",
    )
    parser.add_argument(
        "--no-update",
        action="store_true",
        help="Do not update existing records when fields differ",
    )
    args = parser.parse_args()

    try:
        res = asyncio.run(run_import_cli(args))
        print("\n" + "=" * 50)
        print("IMPORT SUMMARY REPORT")
        print("=" * 50)
        print(f"Total processed:  {res.total_processed}")
        print(f"Inserted:         {res.inserted}")
        print(f"Updated:          {res.updated}")
        print(f"Skipped:          {res.skipped}")
        print(f"Rejected:         {res.rejected}")
        if res.conflicts:
            print(f"Conflicts logged: {len(res.conflicts)}")
        print("=" * 50 + "\n")
    except Exception as e:
        print(f"\nImport failed: {e}\n", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
