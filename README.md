# Breach Checker

A command-line tool for checking whether a password or email address has
appeared in known public data breaches — built with the same k-anonymity
approach used by [Have I Been Pwned](https://haveibeenpwned.com/), so your
actual password is never sent over the network.

## Features

- **Password check** — tests a password against the Pwned Passwords API
  using k-anonymity (only a 5-character hash prefix is transmitted) and
  reports how many times it's shown up in known breaches.
- **Local strength estimate** — quick, fully offline heuristic feedback on
  length, character variety, and repetition, shown alongside the breach result.
- **Email check** — tests an email address against the
  [XposedOrNot](https://xposedornot.com/) breach database.
- **Breach directory** — browse the largest publicly known breaches by
  number of accounts affected.
- **Breach lookup** — look up full details (date, exposed data types, domain)
  for a specific named breach.

## Privacy

Nothing you enter is written to disk, logged, or sent anywhere except the
official API endpoints listed below. Password input is hidden at the
terminal (via `getpass`) and is never stored, even temporarily.

## APIs used

| Purpose            | Provider      | Endpoint                                   |
|--------------------|---------------|---------------------------------------------|
| Password check     | Have I Been Pwned | `api.pwnedpasswords.com/range/{prefix}` |
| Email check        | XposedOrNot   | `api.xposedornot.com/v1/check-email/{email}` |
| Breach directory    | Have I Been Pwned | `haveibeenpwned.com/api/v3/breaches`   |
| Breach lookup       | Have I Been Pwned | `haveibeenpwned.com/api/v3/breach/{name}` |

All are free, public endpoints that don't require an API key.

## Getting started

```bash
git clone https://github.com/<your-username>/breach-checker.git
cd breach-checker
pip install -r requirements.txt
python breach_checker.py
```

## Requirements

- Python 3.10+ (uses `X | Y` union syntax in type hints)
- `requests`

## Disclaimer

This is a personal/portfolio project for educational and defensive-security
purposes — checking your own credentials against known breach data. It is
not affiliated with Have I Been Pwned or XposedOrNot.

## License

MIT — see [LICENSE](LICENSE).
