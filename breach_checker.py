"""Small terminal utility for checking breach information.

Passwords are checked with HIBP's range API. The password itself is never
sent to that service. Email lookups use XposedOrNot's public API.
"""

from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass
from getpass import getpass
from typing import Any
from urllib.parse import quote

import requests


TIMEOUT_SECONDS = 10
HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
HIBP_API_URL = "https://haveibeenpwned.com/api/v3"
XON_EMAIL_URL = "https://api.xposedornot.com/v1/check-email/{email}"

# HIBP asks API clients to identify themselves. This is not an API key.
HIBP_HEADERS = {"user-agent": "breach-checker-cli/1.0"}


def password_breach_count(password: str) -> int:
    """Return the number of known appearances of a password."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, wanted_suffix = digest[:5], digest[5:]

    # Padding makes the response size less revealing to a network observer.
    response = requests.get(
        HIBP_RANGE_URL.format(prefix=prefix),
        headers={"Add-Padding": "true"},
        timeout=TIMEOUT_SECONDS,
    )
    response.raise_for_status()

    for row in response.text.splitlines():
        suffix, _, count = row.partition(":")
        if suffix == wanted_suffix:
            return int(count)
    return 0


def email_breaches(email: str) -> list[str]:
    """Look up an address through XposedOrNot's public endpoint."""
    url = XON_EMAIL_URL.format(email=quote(email, safe=""))
    response = requests.get(url, timeout=TIMEOUT_SECONDS)
    if response.status_code == 404:
        return []
    response.raise_for_status()

    # The free endpoint returns a list containing the list of breach names.
    data = response.json()
    groups = data.get("breaches", [])
    return groups[0] if groups else []


def all_breaches() -> list[dict[str, Any]]:
    response = requests.get(
        f"{HIBP_API_URL}/breaches", headers=HIBP_HEADERS, timeout=TIMEOUT_SECONDS
    )
    response.raise_for_status()
    return sorted(response.json(), key=lambda breach: breach["PwnCount"], reverse=True)


def breach_details(name: str) -> dict[str, Any] | None:
    url = f"{HIBP_API_URL}/breach/{quote(name, safe='')}"
    response = requests.get(url, headers=HIBP_HEADERS, timeout=TIMEOUT_SECONDS)
    if response.status_code == 404:
        return None
    response.raise_for_status()
    return response.json()


@dataclass
class PasswordRating:
    score: int
    name: str
    suggestions: list[str]


def rate_password(password: str) -> PasswordRating:
    """Quick local hint, not a substitute for a proper password manager."""
    score = 0
    suggestions: list[str] = []

    if len(password) >= 12:
        score += 1
    else:
        suggestions.append("Use at least 12 characters.")

    if any(ch.islower() for ch in password) and any(ch.isupper() for ch in password):
        score += 1
    else:
        suggestions.append("Mix upper- and lowercase letters.")

    if any(ch.isdigit() for ch in password):
        score += 1
    else:
        suggestions.append("Add a number.")

    if any(not ch.isalnum() for ch in password):
        score += 1
    else:
        suggestions.append("Add a symbol.")

    if len(set(password)) >= len(password) * 0.6:
        score += 1
    else:
        suggestions.append("Avoid obvious repeated characters.")

    names = ("Very weak", "Weak", "Fair", "Good", "Strong", "Excellent")
    return PasswordRating(score, names[score], suggestions)


def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def wait_for_enter() -> None:
    input("\nPress Enter to return to the menu...")


def heading(text: str) -> None:
    clear()
    print(f"\n{text}\n{'-' * len(text)}")


def show_password_check() -> None:
    heading("Password breach check")
    password = getpass("Password (input is hidden): ")
    if not password:
        print("Nothing entered.")
        return

    try:
        count = password_breach_count(password)
    except requests.RequestException as error:
        print(f"Couldn't check that password: {error}")
        wait_for_enter()
        return

    if count:
        print(f"\nThis password appears in {count:,} known breaches.")
        print("Don't keep using it—especially anywhere it has been reused.")
    else:
        print("\nNo match was found in the Pwned Passwords data set.")

    rating = rate_password(password)
    print(f"\nLocal password check: {rating.name} ({rating.score}/5)")
    for suggestion in rating.suggestions:
        print(f"- {suggestion}")
    wait_for_enter()


def show_email_check() -> None:
    heading("Email breach check")
    email = input("Email address: ").strip().lower()
    if not email:
        print("Nothing entered.")
        return

    try:
        breaches = email_breaches(email)
    except requests.RequestException as error:
        print(f"Couldn't check that address: {error}")
        wait_for_enter()
        return

    if not breaches:
        print(f"\nNo known exposure was found for {email}.")
    else:
        print(f"\n{email} appears in {len(breaches)} known breach(es):")
        for breach in breaches:
            print(f"- {breach}")
    wait_for_enter()


def show_largest_breaches() -> None:
    heading("Largest known breaches")
    try:
        breaches = all_breaches()
    except requests.RequestException as error:
        print(f"Couldn't load the breach directory: {error}")
        wait_for_enter()
        return

    print(f"{len(breaches):,} breach records returned. Top ten by affected accounts:\n")
    for breach in breaches[:10]:
        print(f"{breach['Title']:<22} {breach['PwnCount']:>15,}  {breach['BreachDate']}")
        data_classes = ", ".join(breach.get("DataClasses", [])[:3])
        if data_classes:
            print(f"{'':22} {data_classes}")
    wait_for_enter()


def show_breach_lookup() -> None:
    heading("Find a breach")
    name = input("Breach name (for example, Adobe): ").strip()
    if not name:
        print("Nothing entered.")
        return

    try:
        breach = breach_details(name)
    except requests.RequestException as error:
        print(f"Couldn't look that up: {error}")
        wait_for_enter()
        return

    if breach is None:
        print(f"No breach called {name!r} was found.")
    else:
        print(f"\n{breach['Title']} ({breach.get('Domain') or 'no domain listed'})")
        print(f"Breach date: {breach['BreachDate']}")
        print(f"Accounts affected: {breach['PwnCount']:,}")
        print("Data exposed: " + ", ".join(breach.get("DataClasses", [])))
    wait_for_enter()


def main() -> None:
    actions = {
        "1": show_largest_breaches,
        "2": show_breach_lookup,
        "3": show_password_check,
        "4": show_email_check,
    }

    while True:
        heading("Breach checker")
        print("1. View the largest known breaches")
        print("2. Find one breach by name")
        print("3. Check a password")
        print("4. Check an email address")
        print("5. Quit")

        choice = input("\nChoose an option: ").strip()
        if choice == "5":
            return
        try:
            actions[choice]()
        except KeyError:
            print("Please enter a number from 1 to 5.")
            wait_for_enter()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nBye.")
        sys.exit(0)
