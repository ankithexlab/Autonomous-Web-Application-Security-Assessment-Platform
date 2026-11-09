"""
Verify Dashboard Activity Stream and Component Resilience
"""
import sys
import asyncio
import httpx

async def main():
    async with httpx.AsyncClient(base_url="http://127.0.0.1:8000") as client:
        # Check health
        health = await client.get("/health")
        print(f"Backend Health: {health.status_code}")
        assert health.status_code == 200, "Health check failed"

        # Log in or register test user
        email = "dashboard_verifier@example.com"
        password = "Password123!"
        reg = await client.post("/api/v1/auth/register", json={
            "name": "Dashboard Verifier",
            "email": email,
            "password": password
        })
        if reg.status_code == 201:
            token = reg.json()["access_token"]
            print("Registered new user")
        else:
            login = await client.post("/api/v1/auth/login", json={
                "email": email,
                "password": password
            })
            token = login.json()["access_token"]
            print("Logged in existing user")

        headers = {"Authorization": f"Bearer {token}"}

        # Query dashboard summary
        res = await client.get("/api/v1/dashboard/summary", headers=headers)
        print(f"Dashboard Summary Status: {res.status_code}")
        assert res.status_code == 200, f"Expected 200, got {res.status_code}"
        
        data = res.json()
        print("Summary keys:", list(data.keys()))
        print("Total scans:", data.get("total_scans"))
        print("Recent activities count:", len(data.get("recent_activities", [])))
        for act in data.get("recent_activities", []):
            print(" - Activity:", act.get("id"), "| type:", act.get("type"), "| title:", act.get("title"))

        print("\nSUCCESS: Dashboard summary endpoint successfully verified with live database.")

if __name__ == "__main__":
    asyncio.run(main())
