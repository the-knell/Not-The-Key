# Phase 4 — Gold-standard live proof, own instance only (2026-11-04, box, localhost)

Instance: ghcr.io/home-assistant/home-assistant:2026.11.0 (image digest sha256:c6c1ca9931036bf3a2c4cc088d8db25dfea3b33935a5ecc83c40349462e2f69e), container ha-proof, 127.0.0.1:8123 only, config at /opt/muse/audits/ha/instance/config. Driver: proof/drive.py + proof/fix2.py (run inside the container's own python/aiohttp). Full log: proof/LOG.txt. Two aborted runs precede the clean run (driver bugs: a shadowed urllib import; a WS tuple-logging crash AFTER the password change had already been sent — instance wiped and re-run clean; one login-flow payload defect — submit step also requires client_id — found and fixed in fix2.py). The clean run, 2026-11-04T19:28:12–19:30:02Z:

1. Onboarding created owner user proofowner (password PW1) → auth_code → POST /auth/token authorization_code exchange: 200, access token (expires_in=1800) + normal refresh token R1.
2. GET /api/ with access token: 200.
3. WS auth/long_lived_access_token (client_name proof-script, lifespan 3650 — the exact value the frontend hardcodes): success. Token list showed normal (expire_at 2027-02-02 = creation + 90 days) and long_lived_access_token (expire_at null). LLAT JWT decoded: exp − iat = 315,360,000 s = exactly 3650.0 days. GET /api/ with LLAT pre-change: 200.
4. ATTACKER STEP: host copied config/.storage/auth (mode 600 on disk, verified by stat) to proof/stolen_auth.json. Parsed copy: 3 refresh-token entries — system, normal, long_lived_access_token — each carrying "token" (128 chars) and "jwt_key" (128 chars) in cleartext (redacted excerpt in evidence/stolen_auth_excerpt.json). The copied normal refresh string is byte-identical to the live R1 (driver-verified equality check, STEP5).
5. Password changed through the real WS command config/auth_provider/homeassistant/change_password (current PW1 → new PW2): success=True.
6. PROOF A — copied refresh token alone, after the password change: POST /auth/token grant_type=refresh_token with the COPIED string → 200, fresh access token; GET /api/ → 200; GET /api/config → 200.
7. PROOF B — the pre-change 10-year LLAT, after the password change: GET /api/ → 200; GET /api/config → 200.
8. The password change was real: login flow with OLD password → form error {"base": "invalid_auth"}; with NEW password → create_entry with result code.
9. Negative control: garbage bearer → 401.
10. Manual revocation is the only kill: after WS auth/delete_refresh_token for the normal parent (part 1; the server closed that WS when its own backing token died), the copied refresh grant → 400 {"error": "invalid_grant"}. LLAT still returned 200 at that point; after its parent was deleted via an LLAT-authenticated WS (part 2), GET /api/ with the LLAT → 401. Final .storage/auth contains only the system (content) token.

Container stopped after the proof; instance and all proof artifacts remain on the box under /opt/muse/audits/ha/ (proof/, instance/). The full stolen_auth.json (disposable instance, all user tokens revoked or dead with the container) is retained on the box only; the workspace mirror carries the redacted excerpt + hashes.
