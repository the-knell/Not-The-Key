#!/usr/bin/env python3
"""HA proof part 2: login verification + manual-revocation completion."""
import json, time, urllib.request, urllib.error, urllib.parse, asyncio
from datetime import datetime, timezone

BASE = "http://127.0.0.1:8123"
CLIENT_ID = "http://127.0.0.1:8123/"
PW1 = "Proof-Pass-1-Initial!"
PW2 = "Proof-Pass-2-Changed!"
LOG = open("/proof/LOG.txt", "a", buffering=1)

def log(msg):
    line = f"[{datetime.now(timezone.utc).isoformat()}] {msg}"
    print(line, flush=True); LOG.write(line + "\n")

def http(method, path, data=None, token=None, form=False):
    body = None; headers = {}
    if data is not None:
        if form:
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
    if token: headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(BASE + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw.strip().startswith(("{", "[")) else raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try: return e.code, json.loads(raw)
        except Exception: return e.code, raw

def login(pw):
    st, flow = http("POST", "/auth/login_flow", {
        "client_id": CLIENT_ID, "handler": ["homeassistant", None], "redirect_uri": CLIENT_ID})
    fid = flow["flow_id"]
    return http("POST", f"/auth/login_flow/{fid}", {
        "username": "proofowner", "password": pw, "client_id": CLIENT_ID})

async def ws_delete(access_token, token_id):
    import aiohttp
    async with aiohttp.ClientSession() as s:
        async with s.ws_connect(BASE.replace("http", "ws") + "/api/websocket") as ws:
            await ws.receive_json()
            await ws.send_json({"type": "auth", "access_token": access_token})
            m = await ws.receive_json()
            log(f"FIX2 ws auth with LLAT -> {m.get('type')}")
            await ws.send_json({"id": 1, "type": "auth/delete_refresh_token", "refresh_token_id": token_id})
            try:
                while True:
                    m = await asyncio.wait_for(ws.receive_json(), timeout=5)
                    if m.get("id") == 1:
                        return m
            except Exception as e:
                return {"closed_during_delete": type(e).__name__}

def main():
    log("=== HA PROOF PART 2 ===")
    st, r = login(PW1)
    log(f"FIX-STEP8 login OLD password: type={r.get('type')} errors={r.get('errors')} (expect form + invalid_auth)")
    st, r = login(PW2)
    log(f"FIX-STEP8 login NEW password: type={r.get('type')} has_result={bool(r.get('result'))} (expect create_entry)")

    stolen = json.load(open("/proof/stolen_parsed.json"))
    R1 = stolen["normal_refresh_token"]
    st, body = http("POST", "/auth/token", {
        "grant_type": "refresh_token", "refresh_token": R1, "client_id": CLIENT_ID}, form=True)
    log(f"FIX-STEP10b refresh grant from copied token after its MANUAL revocation in part 1: status={st} body={str(body)[:140]} (expect 400)")

    llat = json.load(open("/proof/llat.json"))
    LLAT, parent = llat["LLAT"], llat["iss"]
    st, _ = http("GET", "/api/", token=LLAT)
    log(f"FIX2 LLAT still valid before deleting its parent: status={st} (expect 200)")
    res = asyncio.run(ws_delete(LLAT, parent))
    log(f"FIX2 delete LLAT parent via LLAT-authenticated WS: {json.dumps(res)[:200]}")
    time.sleep(1)
    st, _ = http("GET", "/api/", token=LLAT)
    log(f"FIX-STEP10c GET /api/ with LLAT AFTER manual revocation of parent: status={st} (expect 401)")
    log("=== HA PROOF PART 2 END ===")

if __name__ == "__main__":
    main()
