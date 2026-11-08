# Not the Key

## Home Assistant's bearer-token custody, its permanent token classes, and the password change that revokes nothing

**knell — 2026-11-04**

---

## Summary

Home Assistant's authentication documentation tells its users: **"Your password is the key to your home, so choose a strong, unique one."** Home Assistant is installed in two million homes by the vendor's own published count, and in those homes it is not an abstraction: it holds the locks, the alarm, the garage, the cameras, and the record of who is home and who is not. This paper tests the sentence against the shipped code — home-assistant/core **2026.11.0**, the frontend package that release ships (**20261028.4**), and hass-nabucasa **2.8.1** — and against a live proof run on our own instance of that exact release.

The password is not the key to the home. The keys to the home are bearer tokens, and this is how they are kept:

1. **Every token secret and every token signing key, for every user, sits in cleartext in one file.** `config/.storage/auth` serializes each refresh token's secret and its per-token JWT signing key verbatim. Passwords in the neighbouring store are bcrypt-hashed; token secrets are not hashed at all, because validation is a direct string comparison against the stored value.
2. **Two of the three token classes never expire.** Only normal refresh tokens carry an expiry — 90 days after *last use*, with the deadline slid forward on every use, so a token in use never reaches it. Long-lived and system refresh tokens are created with `expire_at = None`. The long-lived access tokens the documentation recommends for scripts are valid for ten years, and the core API accepts a caller-supplied lifespan in days with no upper bound at all.
3. **Changing the password revokes none of them.** All four password-change entry points — self-service, administrator, Supervisor reset, command line — rehash the password record and make no token call. This was proven live: after a real password change on our own instance, a refresh token copied from `.storage/auth` beforehand still minted fresh access, and a ten-year long-lived token minted beforehand still authenticated.
4. **The backup key is stored beside the data it protects.** Backups are encrypted by default — that part is real — but the automatic-backup password is persisted in plaintext in `.storage/backup`, in the same directory every backup archives. One read of a live config directory therefore yields the live tokens directly *and* the password that decrypts every exported automatic backup, each of which independently contains the same token file.

Eleven documented claims were checked: **3 hold, 5 hold with a bound, 3 fall.** What is sound is credited in §5 at the same weight: the token generation entropy is impeccable, access tokens live thirty minutes, and the vendor's security response process is funded and real.

One bound belongs in the summary, because the vendor states it plainly and this paper does not hide it: Home Assistant's security page places host and file access outside its threat model. This finding does not cross a privilege boundary, and §7 states the posture in full. The finding is a *conversion*: the construction takes any single read of the installation's most-copied artifacts — the config directory, an exported backup, a synced folder, a support bundle — and converts it into permanent, password-change-proof control of a physical home, surviving the one remediation users are taught to perform. That conversion, not a privilege boundary, is the finding.

## 1. The construction

### 1.1 Custody: one file, in cleartext

Home Assistant has three refresh-token classes (`homeassistant/auth/models.py`): `normal`, `system`, and `long_lived_access_token`. Every credential that can act as a user reduces to a refresh token of one of these classes, plus the access tokens minted from it.

The `AuthStore` serialization (`homeassistant/auth/auth_store.py`, the `_async_save` data builder) writes each refresh token into `config/.storage/auth` with two fields in cleartext:

- `"token": refresh_token.token` — the refresh secret itself;
- `"jwt_key": refresh_token.jwt_key` — the per-token key that signs and validates that token's access-token JWTs.

Validation of a presented refresh token is `hmac.compare_digest` against the stored cleartext string (`async_get_refresh_token_by_token`). The secret cannot be hashed without changing the validation construction, and it has not been: in the same directory, the password store (`homeassistant/auth/providers/homeassistant.py`) keeps passwords bcrypt-hashed at rounds=12, while every token secret and every JWT signing key for every user sits in one JSON file at mode 0600.

The consequence is exact: a read of `.storage/auth` yields every live refresh secret — directly replayable at `POST /auth/token` under the standard refresh grant — together with the signing keys for every access token those refresh tokens can mint. The file also records each token's `client_id`, which the grant handler checks when one is supplied; that check is no obstacle to a reader of the file, because the `client_id` is in the file.

The same directory read takes more than the house. Webhook capability IDs — `secrets.token_hex(32)`, unauthenticated by design — live in cleartext in `.storage/core.config_entries`. The Nabu Casa cloud account's Cognito id, access, and refresh tokens live in cleartext JSON at `config/.cloud/production_auth.json` (mode 0600; hass-nabucasa `__init__.py`, `Cloud.update_token` / `_write_user_info`). §3 returns to the cloud account; the point here is that the config directory is a single shelf, and everything on it is in cleartext.

### 1.2 The expiry matrix

Token generation is sound, and §5 says so. The failure is in how long the products of that sound generation live:

| Class | Expiry | Mechanism |
|---|---|---|
| Access token (JWT, HS256, per-token key) | 30 minutes by default | `exp` at mint; dies with its parent, because parent deletion removes the signing key validation depends on |
| Normal refresh token (browser/app logins) | 90 days after **last use** | `expire_at = now + 90 days` at creation (`homeassistant/auth/__init__.py:507–509`); every access-token mint slides the deadline forward (`AuthStore.async_log_refresh_token_usage`, `auth_store.py:281–286`) |
| Long-lived access token (scripts) | **10 years** as shipped; **unbounded** in the core API | WebSocket command `auth/long_lived_access_token` (`homeassistant/components/auth/__init__.py:637–666`) takes a caller-supplied `lifespan` in days with no upper bound in core; the shipped frontend hardcodes 3650 (`ha-long-lived-access-token-dialog.ts:226`). Its parent refresh token never expires |
| System refresh token (Supervisor legacy, Cast, HTTP content user) | **Never** | Created with `expire_at = None` (`auth/__init__.py:507–509`) |

Two of the three refresh classes are created with `expire_at = None` and no sweeper will ever reach them; the expiry sweeper removes only tokens past a deadline, and only the normal class can have one. The third class's deadline is a deadline on *disuse*: a normal token that is used — by its owner, or by anyone holding a copy — renews itself indefinitely.

One documentation sentence deserves its exact bound. The contributors' authentication API documentation says of the long-lived access token: "Home Assistant does not store it, so it cannot be shown again." Of the JWT *string*, that is true. The string's parent refresh token and its JWT signing key are stored, in cleartext, in `.storage/auth` — and the parent string, in the same file, re-mints equivalent tokens through the standard refresh grant. What is not stored is the one artifact that matters least.

### 1.3 Revocation semantics

The revocation paths that exist are these, each verified by call path:

- **Manual per-token deletion** — the profile Security list, the WebSocket command `auth/delete_refresh_token` (`components/auth/__init__.py:708–729`), or RFC 7009 `POST /auth/revoke` by anyone holding the string.
- **Manual delete-all** — `auth/delete_all_refresh_tokens` (`components/auth/__init__.py:731–769`). Note the frontend's own profile "delete all" button does less than the command allows: `ha-refresh-tokens-card.ts:324` calls it for the `normal` type only, keeping the current token — the shipped UI's bulk action leaves long-lived parents and system tokens alive.
- **User deletion** — removes all of the user's refresh tokens. The owner account cannot be deleted.
- **User deactivation** — removes all refresh tokens. The owner account cannot be deactivated.
- **Credential removal** — removes only tokens bound to that credential.
- **The opt-in frontend prompt** — §4 gives this its full strength.

And the password change. There are four entry points, and all four were read end to end:

1. **Self-service** — WebSocket `config/auth_provider/homeassistant/change_password` (`components/config/auth_provider_homeassistant.py:131–168`): verifies the current password, then calls the provider's `async_change_password`, which is `Data.change_password` (`auth/providers/homeassistant.py:180–196`): rehash and save. No token call appears anywhere in the body.
2. **Administrator change** — the owner-only admin command (`:170–205`): the same single provider call. The frontend's admin dialog likewise performs the change and nothing else.
3. **Supervisor password reset** — `POST /api/hassio_auth/password_reset` (`components/hassio/auth.py`): the same provider call, only.
4. **Command line** — `homeassistant/scripts/auth.py change_password`: the provider's `change_password`, only.

In a typical home the primary account is the owner — the one account that cannot be deleted or deactivated. For that account, after a password change, the complete list of mechanisms that can kill a stolen token is: find it in the profile list and delete it by hand, or have accepted a frontend prompt that three of the four change paths never show (§4).


## 2. The live proof

The construction was proven on our own instance — the official image `ghcr.io/home-assistant/home-assistant:2026.11.0` (digest `sha256:c6c1ca99…`), bound to localhost only, disposable config, no third-party instance touched. The full timestamped log is retained with the audit evidence. The clean run, 2026-11-04:

1. **Setup.** Onboarding created an owner user. The standard authorization-code exchange returned an access token (`expires_in` 1800 seconds — the documented thirty minutes) and a normal refresh token, **R1**.
2. **Baseline.** `GET /api/` with the access token: **200**.
3. **The ten-year token.** Over the WebSocket API, `auth/long_lived_access_token` with `lifespan` 3650 — the exact value the shipped frontend hardcodes — minted a long-lived access token. Its JWT decoded to `exp − iat = 315,360,000` seconds: exactly 3650.0 days. The token list showed the normal token with an expiry ninety days out and the long-lived token's parent with `expire_at` null. `GET /api/` with the long-lived token: **200**.
4. **The theft.** From the host, `config/.storage/auth` (mode 0600 on disk, verified) was copied out. The copy held three refresh-token entries — system, normal, long-lived — each carrying its `token` and its `jwt_key` in cleartext, 128 characters each. The copied normal refresh string was byte-identical to the live R1, verified by the driver.
5. **The password change.** The password was changed through the real WebSocket command `config/auth_provider/homeassistant/change_password`, current password to new password: success.
6. **The change was real.** A login flow with the *old* password returned `invalid_auth`; with the *new* password it succeeded. Whatever follows is not an artifact of a failed change.
7. **The stolen material still works.** From the copied material alone, after the change: (a) `POST /auth/token` with the copied refresh token under the refresh grant returned **200** and a fresh access token, with which `GET /api/` and `GET /api/config` both returned **200**; (b) the ten-year long-lived token minted *before* the change, presented after it, returned **200** on `GET /api/` and `GET /api/config`.
8. **Controls.** A garbage bearer token: **401**.
9. **The only kill.** Manual per-token deletion of the normal parent: the copied refresh grant then returned **400 `invalid_grant`** — and, instructively, the long-lived token *still returned 200* at that point, because its parent is a separate record. Only after the long-lived parent was itself deleted did the ten-year token return **401**. The final `.storage/auth` contained only the system token.

Nothing in the proof crosses a boundary the vendor claims. It demonstrates one thing: the remediation the documentation teaches — change the password — leaves every previously issued or copied credential in force, and in two classes in force without limit of time.

## 3. The backup kicker, and the cloud

**Backups.** The backup documentation says "Backups are encrypted by default," and at the pin that is true: per-agent protection defaults to on (`components/backup/config.py:208`), the cloud agent refuses unprotected backups outright ("Cloud backups must be protected," `components/cloud/backup.py:118–119`), and protected archives are SecureTar-encrypted. The bound is where the key lives. The automatic-backup password is persisted **in plaintext in `.storage/backup`** — the code says so itself, in a comment in `components/backup/store.py:39–43`: *"The store persists the automatic backup password in plaintext."*

A settings backup contains the config folder — `.storage` included — so every backup carries a copy of `.storage/auth`. And a restore resurrects the token state of the backup era wholesale; the vendor's own documentation instructs users, on the post-restore login screen, to enter the password "as they were at the time the backup was taken." Yesterday's tokens, restored, are live tokens.

The net construction: one read of a live config directory yields (a) the live token secrets directly, and (b) the password that decrypts every exported automatic backup that installation has ever made, each of which independently contains the same token file. A backup archive *alone*, divorced from the live directory, remains protected by its password — that part of the design holds, and §4 scores it so.

**The cloud.** The backup documentation also says "Nabu Casa does not store your encryption key," and that holds — because the key never leaves the box; it sits on the instance, in plaintext, beside the data (above). The remote-access path itself is better built than the token layer, and this paper credits it: TLS for the remote UI **terminates at the instance**, under an ACME certificate issued to the instance's own domain with the private key held locally (`hass-nabucasa` 2.8.1, `remote.py:438–455` — the local context is loaded into the local aiohttp runner, which the SniTun client wraps). The relay routes by SNI and holds no Home Assistant session material, no HA token, and no TLS key. Arriving through the tunnel still requires ordinary HA authentication, and `local_only` users are refused on cloud connections. A cloud-account compromise yields control of the instance's remote registration and domain routing, cloudhooks, voice pipelines, cloud backups, and subscription — and **no HA token**: no code path in core's cloud component or in hass-nabucasa mints HA auth tokens from cloud credentials. The join between the two systems is on disk, not in protocol: the cloud account's Cognito refresh token sits in plaintext in the same config directory, so the single file read that takes the house takes the cloud account with it.

## 4. The claims table

Eleven claims, taken verbatim from the vendor's security page, authentication documentation, contributors' documentation, and backup documentation, scored against the pinned code and the live proof:

| # | Claim (source) | Verdict |
|---|---|---|
| C1 | "Home Assistant takes its security seriously. We will do everything in our power to ensure that our users are safe." (security page) | **HOLDS WITH BOUND** — true of the response process (advisory history, funded audits); the token custody construction in §1 is the bound |
| C2 | Security posture: attacks requiring host access are non-qualifying; "Home Assistant assumes every user is trusted… every logged in user has the same access as an owner account" (security page) | **HOLDS** — as a stated posture; it is also why this paper claims durability of stolen material, not privilege escalation (§7) |
| C3 | "Your password is the key to your home" (auth docs) | **FALLS** — the keys to the home are the bearer tokens in `.storage/auth`; the password is one way to mint them, and changing it revokes none of them (§1, §2) |
| C4 | "Delete one [refresh token] to force that device to sign out"; unused tokens auto-removed at 90 days; long-lived token recommended "if you need a permanent token" (auth docs) | **HOLDS WITH BOUND** — all three sentences are code-true; the bound is that "unused" slides forward on every use, and two other classes are permanent by construction, not by recommendation |
| C5 | Password change: "Home Assistant asks whether you want to sign out of all other sessions…" (auth docs) | **HOLDS WITH BOUND** — the prompt exists; see below |
| C6 | Refresh token "expires when it has not been used for 90 days"; LLATs "valid for 10 years"; "Home Assistant does not store it [the LLAT]" (contributors auth API) | **HOLDS WITH BOUND** — the LLAT *string* is not stored; its never-expiring parent refresh token and its JWT signing key are stored in cleartext, and the parent string re-mints equivalents via the standard refresh grant |
| C7 | Access token 30 minutes; refresh revocable from profile at any time (contributors internals) | **HOLDS** |
| C8 | "Backups are encrypted by default"; settings backups include the config folder; post-restore, logins use the credentials "as they were at the time the backup was taken" (backup docs) | **HOLDS WITH BOUND** — the encryption default is real (per-agent; cloud mandatory); the bound is §3: the backup password is stored plaintext beside the data |
| C9 | "Nabu Casa does not store your encryption key" (backup docs) | **HOLDS** — true of the vendor; the key is instead stored on the instance itself, in plaintext (§3) |
| C10 | *(Implicit across the auth docs)* Changing your password is the response to a compromised account | **FALLS** — §1.3, §2 |
| C11 | *(Implicit)* A stolen long-lived access token can be neutralised by changing the password | **FALLS** — §2, step 7: proven live |

**The C5 nuance, at full strength in the vendor's favor.** The prompt the documentation describes exists and works. In the shipped web frontend (`ha-change-password-card.ts`, frontend 20261028.4), after a self-service password change succeeds, the user is shown a confirmation dialog asking whether to sign out of all other sessions; answering Yes invokes `auth/delete_all_refresh_tokens` with the core defaults, which delete **all** token types, including the current one. A user who changes their password in the web UI and accepts that prompt has performed a complete revocation. The audit states this without qualification.

It does not cure F1, for four reasons, each a code fact rather than an interpretation:

1. **It is not part of the password change.** The backend change — the operation every path performs — revokes nothing. The prompt is a separate, subsequent frontend action layered on one client's flow.
2. **It is opt-in.** The default posture of the flow is a dialog the user can decline, presented after the change has already succeeded; a user who has just "secured" their account by changing the password is being asked, as an afterthought, whether to also do the thing that actually secures it.
3. **It is frontend-only.** It does not exist in the administrator change path, the Supervisor password-reset path, or the command-line path. An owner whose account is reset by an admin or through Supervisor — precisely the compromise-recovery scenarios — is never offered it.
4. **The one exercised path was not the live proof's.** The live proof exercised the backend change command exactly as the frontend's first step performs it; the opt-in flow itself is code-proven at the frontend pin and disclosed as unexercised in §7. Nothing in the verdict depends on it either way: C5 is scored HOLDS WITH BOUND *because* the prompt exists, and C3/C10/C11 fall because the password change, as an operation, revokes nothing.


## 5. What is sound, credited

The following were read and verified at the same weight as the findings, and are credited without qualification:

- **Generation entropy, everywhere it was checked.** Refresh secrets are `secrets.token_urlsafe(64)`; per-token JWT keys are `secrets.token_hex(64)`; webhook IDs are `secrets.token_hex(32)`. There is no weak-RNG call site in the token layer. The failure in this paper is custody, expiry classes, and revocation semantics — not entropy.
- **Access tokens are short and narrow.** Thirty minutes by default; each signed with its own token's key, so one token's key compromise signs nothing else; a ten-second validation leeway and no more.
- **Passwords are handled properly.** Bcrypt at rounds=12, with dummy-hash timing equalisation for unknown users.
- **The Supervisor's migration is the model the rest of the system should follow.** Supervisor no longer authenticates with refresh tokens at all — it uses a dedicated Unix socket — and its legacy refresh tokens are proactively removed at setup. A permanent credential class was identified, retired, and cleaned up. It can be done; it was done, there.
- **Backup encryption defaults are real,** including the cloud agent's hard refusal of unprotected backups, and `.storage` files are written mode 0600.
- **The remote UI's TLS terminates at the instance** (§3), with the private key never leaving the box.
- **The frontend's opt-in sign-out-all prompt exists and works** (§4) — the bound is its placement, not its function.
- **The vendor's response process is funded and real**: a public advisory history and paid security audits stand behind C1's process half, which is why C1 holds in that half.

## 6. Fixes

Each fix is matched to the construction that fails, and none requires new cryptography:

1. **Hash the stored refresh secrets.** Validation is a comparison against a stored value; the stored value can be a hash of the secret exactly as password storage already demonstrates in the neighbouring file. A read of `.storage/auth` should yield verifiers, not replayable credentials. Per-token JWT signing keys can likewise be derived or held apart from the token records they serve, so that one file is never simultaneously the credential store and the signing-key store.
2. **Bind revocation to the password change by default.** A password change — at every entry point, in the backend operation itself — should delete the account's other refresh tokens, with the *exceptions* (keep this session) as the opt-in, not the revocation. The frontend prompt proves the machinery exists; it is in the wrong place and defaults the wrong way.
3. **Expire, or periodically re-confirm, the permanent classes.** Long-lived parents should carry a real expiry, and the core API should bound the caller-supplied `lifespan` rather than accepting an arbitrary number of days. System tokens should be enumerable in the same profile surface as every other credential a user is expected to audit.
4. **Move the backup key off the data's shelf.** The automatic-backup password should not persist in plaintext inside the directory that every backup archives. If unattended scheduled backups require a stored key, it should be stored so that a config-directory read does not yield it alongside the data it decrypts — and exports should warn, in the export flow itself, that a decrypted backup contains live credential state.
5. **Say the true sentence in the documentation.** Until the above lands, the authentication documentation should state what a password change does and does not do, in the same place it currently calls the password "the key to your home."

## 7. Bounds, method, and disclosure

**Method.** Claims were taken verbatim from the vendor's public security page, authentication documentation, contributors' documentation, and backup documentation. Code was read at the pins stated in the summary: core 2026.11.0 (commit `74cf5a49…`, released the day of the audit), frontend 20261028.4 (the exact package that core release ships), hass-nabucasa 2.8.1. The live proof ran only on our own instance of the pinned image, bound to localhost, in a disposable configuration. No third-party instance was touched; no live service was interacted with.

**The vendor's posture, stated plainly.** The security page excludes attacks that require access to the host system from its qualifying scope, and states that Home Assistant assumes every logged-in user is trusted with owner-equivalent access. This paper does not dispute that posture and does not claim a privilege escalation: nothing here lets an unprivileged party become privileged. The claim is narrower and, under the vendor's own posture, still standing: token material, once copied from any of the artifacts an installation routinely produces — its config directory, an exported backup, a synced folder, a migration archive — is *durable*. It survives the remediation the documentation teaches, in two classes it survives indefinitely, and the file that holds it also holds the password that decrypts the backups that hold it again. A posture that declares file access out of scope does not answer a finding about what a file, once read, permanently buys.

**Unexercised and unread, disclosed.** One code path was not exercised live: the frontend's opt-in sign-out-all flow (§4). It is code-proven in frontend 20261028.4 (`ha-change-password-card.ts`) together with the core defaults it invokes; the live proof exercised the backend change command exactly as that flow's first step performs it, and the verdicts are constructed so that nothing rests on the unexercised path. Not read: the companion app (iOS/Android) sources — mobile tokens are treated only as consumers of the normal class through the standard OAuth flow; the Supervisor repository (tar assembly on HAOS is Supervisor-side; core-side inclusion of the config folder is documentation-stated and restore-path-verified); the snitun library internals (the TLS termination point is proven from hass-nabucasa's construction); and the SecureTar package's key derivation (the backup claim concerns key *custody*, not cipher strength). The proof driver failed twice before its clean run — a shadowed import, and a logging crash after a change-password command had already been sent — and the instance was wiped and re-run; the aborted runs are disclosed in the audit record, and no claim rests on them.

**Disclosure.** Vendor notice has not been sent as of signing.

---

*Appendix — numbers at a glance.* Pins: core 2026.11.0 (`74cf5a49c63ed8d4d87717844bf14f79c28c9cea`), frontend 20261028.4 (`a67b691a451e0b3fc469679b07158f963a61842c`), hass-nabucasa 2.8.1 (`6243a1771258c4a53d6e16c235f5586dfd970394`); proof image digest `sha256:c6c1ca9931036bf3a2c4cc088d8db25dfea3b33935a5ecc83c40349462e2f69e`. Access-token lifetime: 1800 s. Normal refresh expiry: 90 days, sliding on use. LLAT as shipped: 3650 days (JWT `exp − iat` measured 315,360,000 s); core lifespan bound: none. Long-lived and system parent expiry: none (`expire_at = None`). Refresh secret length as stored: 128 characters (`secrets.token_urlsafe(64)`); JWT key: 128 hex characters (`secrets.token_hex(64)`). Password hashing: bcrypt, rounds=12. Claims scored: 11 — 3 hold, 5 hold with bound, 3 fall.
