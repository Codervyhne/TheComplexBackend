from flask import Flask, request, jsonify
import requests
import secrets
import time
import hmac
import hashlib
from functools import wraps
from collections import defaultdict

app = Flask(__name__)
app.config["maxlength"] = 16 * 1024  # limit payload size

apikey = ""
secretkey = ""
titleid = ""
webhook = ""

nonces = {}
sessions = {}
user_devices = {}
device_users = {}


session_secret = secrets.token_bytes(64)
ip_requests = defaultdict(list)
RATE_WINDOW = 60
MAX_REQUESTS = 60


def cleanup():
    now = time.time()
    for n in list(nonces.keys()):
        if nonces[n] < now:
            del nonces[n]
    for s in list(sessions.keys()):
        if sessions[s]["expiry"] < now:
            del sessions[s]
    for ip in list(ip_requests.keys()):
        ip_requests[ip] = [t for t in ip_requests[ip] if t > now - RATE_WINDOW]
        if not ip_requests[ip]:
            del ip_requests[ip]


def is_rate_limited():
    ip = request.remote_addr
    now = time.time()

    ip_requests[ip].append(now)
    ip_requests[ip] = [t for t in ip_requests[ip] if t > now - RATE_WINDOW]

    return len(ip_requests[ip]) > MAX_REQUESTS


def sign_token(token):
    signature = hmac.new(session_secret, token.encode(), hashlib.sha256).hexdigest()
    return f"{token}.{signature}"


def verify_token(token):
    try:
        raw, signature = token.rsplit(".", 1)
        expected = hmac.new(session_secret, raw.encode(), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected, signature):
            return None

        return raw
    except:
        return None


def ban_response():
    return jsonify({
        "status": "error",
        "message": "your account has been traced and banned"
    }), 403


def validate_payload(*required_keys):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            cleanup()

            if is_rate_limited():
                log("rate limit", f"IP {request.remote_addr}")
                return ban_response()

            data = request.get_json(silent=True)
            if not isinstance(data, dict) or not all(k in data for k in required_keys):
                log("bad payload", f"{request.remote_addr}")
                return ban_response()

            return func(*args, **kwargs)
        return wrapper
    return decorator


@app.errorhandler(404)
@app.errorhandler(405)
def handle_bad_requests(e):
    log("invalid route", f"{request.remote_addr} tried {request.method} {request.path}")
    return ban_response()


def log(event, message):
    try:
        requests.post(webhook, json={
            "content": f"[{event}] {message}"
        }, timeout=3)
    except:
        pass


def banloser(playfab_id, reason="Security violation"):
    try:
        requests.post(
            f"https://{titleid}.playfabapi.com/Server/BanUsers",
            headers={"X-SecretKey": secretkey},
            json={
                "Bans": [{
                    "PlayFabId": playfab_id,
                    "Reason": reason,
                    "DurationInHours": 127
                }]
            },
            timeout=5
        )
        log("ban", f"{playfab_id} banned: {reason}")
    except:
        pass


@app.route("/v2/attestation/gennonce", methods=["POST"])
def request_nonce():
    cleanup()

    if is_rate_limited():
        return ban_response()

    nonce = secrets.token_hex(32)
    nonces[nonce] = time.time() + 120  # 2 min expiry

    return jsonify({"nonce": nonce})


@app.route("/v2/attestation/quest/MothershipAuthentication", methods=["POST"])
@validate_payload("token", "nonce", "UserId")
def mothership_auth():
    data = request.json
    token = data.get("token")
    nonce = data.get("nonce")
    user_id = data.get("UserId")
    playfab_id = data.get("PlayFabId")

    expiry = nonces.get(nonce)

    if not expiry or expiry < time.time():
        if playfab_id:
            banloser(playfab_id, "Invalid nonce")
        return ban_response()

    # nonce single use
    del nonces[nonce]

    try:
        verify = requests.post(
            "https://graph.oculus.com/platform_integrity/verify",
            data={
                "access_token": apikey,
                "attestation_token": token
            },
            timeout=5
        ).json()

        if "is_tampered" not in verify or "unique_id" not in verify:
            if playfab_id:
                banloser(playfab_id, "Bad attestation response")
            return ban_response()

        if verify["is_tampered"]:
            if playfab_id:
                banloser(playfab_id, "Tampered device")
            return ban_response()

        device_id = verify["unique_id"]

        if user_id in user_devices and user_devices[user_id] != device_id:
            if playfab_id:
                banloser(playfab_id, "Device mismatch")
            return ban_response()

        if device_id in device_users and device_users[device_id] != user_id:
            if playfab_id:
                banloser(playfab_id, "Ban evasion")
            return ban_response()

        user_devices[user_id] = device_id
        device_users[device_id] = user_id

        raw_token = secrets.token_hex(48)
        session_token = sign_token(raw_token)

        sessions[raw_token] = {
            "user_id": user_id,
            "device_id": device_id,
            "ip": request.remote_addr,
            "agent": request.headers.get("User-Agent"),
            "expiry": time.time() + 1800
        }

        return jsonify({
            "status": "CLEAN",
            "session_token": session_token
        })

    except:
        if playfab_id:
            banloser(playfab_id, "Verification failed")
        return ban_response()


@app.route("/v2/auth/PlayFabAuthentication", methods=["POST"])
@validate_payload("CustomId", "session_token")
def playfab_custom_auth():
    data = request.json
    custom_id = data.get("CustomId")
    session_token = data.get("session_token")

    raw_token = verify_token(session_token)
    if not raw_token:
        return ban_response()

    session_data = sessions.get(raw_token)
    if not session_data or session_data["expiry"] < time.time():
        return ban_response()

    # bind session to same IP + device agent
    if session_data["ip"] != request.remote_addr or \
       session_data["agent"] != request.headers.get("User-Agent"):
        return ban_response()

    try:
        response = requests.post(
            f"https://{titleid}.playfabapi.com/Client/LoginWithCustomID",
            json={
                "CustomId": custom_id,
                "CreateAccount": True
            },
            timeout=5
        ).json()

        if response.get("code") != 200:
            return ban_response()

        playfab_id = response["data"]["PlayFabId"]
        session_data["playfab_id"] = playfab_id
        session_data["expiry"] = time.time() + 1800  # sliding expiration

        return jsonify({
            "status": "Cool guy passed auth",
            "PlayFabId": playfab_id,
            "SessionTicket": response["data"]["SessionTicket"]
        })

    except:
        return jsonify({"status": "something went wrong contact a developer"}), 500


@app.route("/v2/api/PhotonAuthentication", methods=["POST"])
@validate_payload("session_token", "UserId")
def photon_auth():
    data = request.json
    session_token = data.get("session_token")
    user_id = data.get("UserId")

    raw_token = verify_token(session_token)
    if not raw_token:
        return ban_response()

    session_data = sessions.get(raw_token)

    if not session_data:
        return ban_response()

    if session_data["expiry"] < time.time():
        del sessions[raw_token]
        return ban_response()

    if session_data["user_id"] != user_id:
        return ban_response()

    # strict binding enforcement
    if session_data["ip"] != request.remote_addr or \
       session_data["agent"] != request.headers.get("User-Agent"):
        return ban_response()

    session_data["expiry"] = time.time() + 1800 # Refresh session ticket

    return jsonify({
        "ResultCode": 1,
        "UserId": user_id,
        "AuthCookie": {
            "verified": True,
            "device_id": session_data["device_id"],
            "playfab_id": session_data.get("playfab_id")
        }
    })


app.debug = False