# 0018 Authentication, sessions and request integrity

Status: Accepted

## Context
Varde shows which apps run where and which of them are vulnerable. That inventory is valuable to an
attacker, so the UI and the API are authenticated without exception (except `/healthz` and
`/readyz`, which reveal nothing). Varde runs on hardware from a Raspberry Pi upwards, often on a
plain-HTTP LAN, sometimes behind a TLS reverse proxy. There is no external identity provider in v1.

## Decision
- **Passwords**: argon2id with the RFC 9106 second recommended profile (t=3, m=64 MiB, p=4, 16-byte
  salt, 32-byte key), stored in PHC string format so parameters can be raised later without a
  migration. Hashes run one at a time, which bounds memory to 64 MiB under a login flood. Minimum
  length 12 characters, maximum 256 bytes. Unknown users go through a dummy hash so timing does not
  reveal account names.
- **First account**: no default credentials. While no account exists, Varde stores the SHA-256 of a
  random one-time setup token, valid 24 hours, and prints the token once to the log. A restart
  replaces an unused token.
- **Sessions**: 32 random bytes in the `varde_session` cookie; only the SHA-256 is stored. Idle
  timeout 24 hours, absolute 7 days, rotation on login and on password change (which also ends all
  other sessions of the account). `HttpOnly` and `SameSite=Strict` always.
- **Secure attribute**: `VARDE_COOKIE_SECURE=auto` (default) sets it when the request arrived over
  TLS, directly or as reported by a trusted proxy; `always` and `never` force it. `never` exists for
  plain-HTTP LANs and makes the UI show a permanent warning.
- **CSRF**: a per-session synchronizer token in a form field or the `X-CSRF-Token` header, plus a
  fetch-metadata check. `Sec-Fetch-Site` is authoritative when present (`same-origin` or `none`);
  only clients without fetch metadata fall back to comparing `Origin` with `Host`. Browsers omit
  fetch metadata on plain-HTTP origins (not a secure context) and may send `Origin: null` there, so
  that combination is left to the tokens. The login and setup forms, posted before a session
  exists, carry a token that must match the `varde_form` cookie (`SameSite=Strict`, double
  submit). The response
  header `Referrer-Policy: same-origin` keeps referrers inside Varde without making browsers send
  `Origin: null` on same-origin form posts.
- **Throttling**: five free failures per account and per client IP, then a delay doubling from one
  second up to 15 minutes. Client IPs from `X-Forwarded-For` are honoured only from
  `VARDE_TRUSTED_PROXIES`.
- **API tokens**: `varde_` prefix plus 32 random bytes, scope `read` (GET only) or `write`, stored as
  SHA-256, shown once at creation. Session-authenticated API writes need the CSRF header. The static
  `VARDE_API_TOKEN` from earlier phases keeps working with write scope.

## Alternatives
- bcrypt: not memory-hard, 72-byte input limit.
- Stateless signed cookies (JWT): no server-side revocation; logout and password change would not
  end other sessions.
- `Origin`-only CSRF protection: breaks under strict referrer policies (browsers send
  `Origin: null`) and is absent on some older clients; the synchronizer token stays the primary
  control.
- OIDC: useful for larger setups, but adds an external dependency most homelabs do not have.
  Possible later as an additional login method.

## Consequences
- A login costs about 64 MiB and, on small ARM boards, a few hundred milliseconds of CPU; the semaphore keeps that bounded.
- Users on plain-HTTP LANs must opt in to `never` or put Varde behind TLS; the UI says which.
- A forgotten password is reset with `varde reset-password <user>` where the server runs
  (`docker exec`): it sets a random password, prints it once, ends the user's sessions and writes an
  audit entry. It needs access to the data volume, which already means full control.
