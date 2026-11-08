# Phase 0 — Pins and claims (HA audit, 2026-11-04)

## Pins (all read at these exact revisions)
- home-assistant/core **2026.11.0**, commit 74cf5a49c63ed8d4d87717844bf14f79c28c9cea, GitHub release id 434238213, published 2026-11-04T17:32:55Z (latest release at audit start). Clone: box /opt/muse/audits/ha/src/core
- home-assistant/frontend **20261028.4**, commit a67b691a451e0b3fc469679b07158f963a61842c — this is the exact package core 2026.11.0 ships (frontend manifest requirement home-assistant-frontend==20261028.4). Clone: box /opt/muse/audits/ha/src/frontend
- NabuCasa/hass-nabucasa **2.8.1**, commit 6243a1771258c4a53d6e16c235f5586dfd970394 — core cloud manifest requirement hass-nabucasa==2.8.1. Clone: box /opt/muse/audits/ha/src/nabucasa. (PyPI on the box tops out at 0.88.1; source taken from the GitHub tag instead.)
- NOT read: companion apps (iOS/Android) source; Supervisor repo; snitun server/library internals beyond the client usage in hass-nabucasa. Stated as bounds in FINDINGS.

## Claims ledger (verbatim, vendor's own text)
C1. Security page (home-assistant.io/security/): "Home Assistant takes its security seriously. We will do everything in our power to ensure that our users are safe."
C2. Security page, non-qualifying: "Attacks that require the user to have access to the Home Assistant host system." Also: "Privilege escalation attacks for logged in users. Home Assistant assumes every user is trusted and does not enforce user privileges. It assumes every logged in user has the same access as an owner account"
C3. Authentication docs (home-assistant.io/docs/authentication/): "Your password is the key to your home, so choose a strong, unique one."
C4. Same: "Manage your Refresh tokens. A refresh token is created each time you sign in from a device. Delete one to force that device to sign out." / "Unused refresh tokens are automatically removed. A refresh token is considered unused if it has not been used to sign in within 90 days. If you need a permanent token, we recommend using a long-lived access token instead."
C5. Same, password change: "Home Assistant asks whether you want to sign out of all other sessions. Select Yes to force every other device to sign in again with the new password, or No to keep them signed in."
C6. Contributors auth API docs: "A refresh token expires when it has not been used for 90 days." / Long-lived access tokens "are valid for 10 years, and are used exactly like an access token." / "Home Assistant does not store it, so it cannot be shown again." (of the minted LLAT string)
C7. Contributors internals: access token "valid for 30 minutes"; refresh token "expires when it has not been used for 90 days, and the user can revoke it from their profile at any time"; types Normal / Long-lived access token / System.
C8. Backup docs (home-assistant.io/common-tasks/general/backups/): "Backups are encrypted by default and stored in a compressed archive file (.tar)." / "Home Assistant settings ... include the config folder" / "If you restore the Home Assistant settings, new backups use the encryption key that is saved in those settings." / "On the login screen, enter the password and username as they were at the time the backup was taken."
C9. Backup docs via community quote of integration docs: "If you have lost the encryption key, and have no access to your Home Assistant instance, there is no way to restore the backup." / "Nabu Casa does not store your encryption key and cannot provide support in decrypting backups if the key goes missing."
