"""
test_api.py
============================================================
UniGuard-AI - Dashboard API Testing
============================================================

Run:
    python test_api.py

Requirement:
    UniGuard-AI dashboard must be running at:
    http://127.0.0.1:5000
============================================================
"""

from __future__ import annotations

import json
import sys
from typing import Any

import requests


# ============================================================
# CONFIGURATION
# ============================================================

BASE_URL = "http://127.0.0.1:5000"


# ============================================================
# PRINT API RESULT
# ============================================================

def print_result(
    name: str,
    response: requests.Response,
) -> None:
    """
    Print the result of an API request.
    """

    print("\n" + "=" * 65)
    print(f"TEST: {name}")
    print("=" * 65)

    print(f"URL         : {response.url}")
    print(f"Status      : {response.status_code}")
    print(
        "Content-Type: "
        f"{response.headers.get('Content-Type')}"
    )

    try:

        data: Any = response.json()

        print("Response    :")

        print(
            json.dumps(
                data,
                indent=4,
                ensure_ascii=False,
            )
        )

    except ValueError:

        print("Response    :")
        print(response.text[:1000])

    if response.ok:

        print("RESULT      : PASS ✅")

    else:

        print("RESULT      : FAIL ❌")


# ============================================================
# TEST ONE ENDPOINT
# ============================================================

def test_endpoint(
    name: str,
    endpoint: str,
) -> bool:
    """
    Test one dashboard API endpoint.
    """

    url = f"{BASE_URL}{endpoint}"

    try:

        response = requests.get(
            url,
            timeout=10,
        )

        print_result(
            name,
            response,
        )

        return response.ok

    except requests.exceptions.ConnectionError:

        print("\n❌ CONNECTION FAILED")
        print("Dashboard is not running.")
        print(
            "Start the dashboard using:"
        )
        print(
            "python main.py --mode passive"
        )

        return False

    except requests.exceptions.Timeout:

        print("\n❌ REQUEST TIMED OUT")
        print(f"URL: {url}")

        return False

    except requests.exceptions.RequestException as exc:

        print("\n❌ REQUEST ERROR")
        print(str(exc))

        return False


# ============================================================
# MAIN TEST RUNNER
# ============================================================

def main() -> None:
    """
    Run all supported dashboard API tests.
    """

    print("=" * 65)
    print("🛡️ UNIGUARD-AI API TESTING")
    print("=" * 65)
    print(f"Base URL: {BASE_URL}")

    # ========================================================
    # SUPPORTED API ENDPOINTS
    # ========================================================

    tests = [
        (
            "Dashboard Home",
            "/",
        ),
        (
            "Throughput Statistics",
            "/api/stats/throughput",
        ),
        (
            "Performance Statistics",
            "/api/stats/performance",
        ),
        (
            "Threat Summary",
            "/api/threats/summary",
        ),
        (
            "All Threat Alerts",
            "/api/threats/alerts",
        ),
        (
            "Open Threat Alerts",
            "/api/threats/alerts/open",
        ),
    ]

    passed = 0
    failed = 0

    # ========================================================
    # EXECUTE TESTS
    # ========================================================

    for name, endpoint in tests:

        result = test_endpoint(
            name,
            endpoint,
        )

        if result:

            passed += 1

        else:

            failed += 1

    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    print("\n" + "=" * 65)
    print("API TEST SUMMARY")
    print("=" * 65)

    print(f"Total Tests : {len(tests)}")
    print(f"Passed      : {passed}")
    print(f"Failed      : {failed}")

    if failed == 0:

        print("\n🎉 All API tests passed successfully!")

    else:

        print(
            "\n⚠️ Some API tests failed."
        )

        sys.exit(1)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()