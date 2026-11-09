"""Verify PostgreSQL database records for security_payloads."""

import asyncio
from sqlalchemy import text
from app.database.session import engine


async def main():
    async with engine.connect() as conn:
        total = await conn.execute(text("SELECT COUNT(*) FROM security_payloads"))
        print(f"Total security_payloads: {total.scalar()}")

        sevs = await conn.execute(
            text("SELECT severity, COUNT(*) FROM security_payloads GROUP BY severity ORDER BY COUNT(*) DESC")
        )
        print("Severity distribution:")
        for row in sevs.fetchall():
            print(f"  {row[0]}: {row[1]}")

        types = await conn.execute(
            text("SELECT type, COUNT(*) FROM security_payloads GROUP BY type ORDER BY COUNT(*) DESC")
        )
        print("Type distribution:")
        for row in types.fetchall():
            print(f"  {row[0]}: {row[1]}")

        csrf = await conn.execute(text("SELECT COUNT(*) FROM security_payloads WHERE id = 'csrf-039'"))
        print(f"csrf-039 count in database: {csrf.scalar()}")


if __name__ == "__main__":
    asyncio.run(main())
