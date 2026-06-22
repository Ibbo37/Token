import os
import uuid
import time
import requests
import jwt  # PyJWT
from flask import Flask, request, jsonify

app = Flask(__name__)

# ─────────────────────────────────────────────
# CONFIG — replace values if they change
# ─────────────────────────────────────────────
PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDc6WzU7xncyMTr
pOm24abgDQtMnsIEvrPCdNaff4vk2ewpJZXlIMQVvnYa5FwV0twulDkYVEnfsdwg
2x32h9mH7JNlciKGm/Ka1dugiDGk0APV98JExtJp7Djpka8V/1pGpOXLtj/vM2+z
SJWQxvyYVE54sGW23KGXStd7u2wap7507/q4AEYCM3x9SongN8Q2B/qqNqGO4W2J
JQ9xkGlNAprT+9Mgb1+ksL+otsPHT99UwD+50N2IbYIUNIlAXEfn6xja5JPCVLEd
dmSquAAO5TMNzYPbIiTN/owyV8bqnOK1AOhl9QMSwhyvkiyzo9rIc2dQ9vpwfd8g
iffdOk59AgMBAAECggEACJaDflioOPrOGvoPguZNUjb3mjwuvzf5rYTUxiETe2tU
YLofFGf8b3r2xO9dPBT1LdNhz9YRBCL6M4XJKakY1g2mokI4YOLFoOrQ7bH1uhpD
F+mYkgtnqSn/gWcCNzj01bu52jxEyoQFouLeu6Dct4BJh6wV3DDCEGteqqb72iJa
QJwZRlqmNt52wlG+nBTkkCXXNgAvpABP0KmPWxZJS10/5NSZGrKxgSCYg+1FfVJl
GQNURIj7k4psEiTg9XYXHfJq60wtfKFJciUpGsRBfTl8RYtRnYD1qoJtZCvcbOS1
T0OGS0dFrsbsLoaWCi4kiOyQmSu85s4sMZ1+NE/6EQKBgQD9Ms6JBj0ZB2FONsJK
DDVAb1s82twnlNpd9VkpZZXzdxuThMhdNCeYD4oEUtY7Eb7XLCEBygrGM2vOHDVn
6pClX+WvGYHuxaXkq63NcckNqCudmvFhum/4qCbv4zav/teenT5BR5+dMRXXdnl6
hn9Nq6JrWvUt4aBRa7OaB5pD0QKBgQDfWypSudVn9c3fUcK2D7H2/5Tqo+5R3bJf
vQ5wsg8SHktiCRdh/34YItG17q35tzYBG/GVN8SsV76yOpH4+6jCmyjFTAOWD1HS
NC2ZXWwFEUsuTVipy240ioO+g02+WMDzNWTMRBUk90p02yuUbrAsPgpU1nKIACzb
rPspIHCm7QKBgQCrRTHWGGU9x/M3P+0+v3FKC8lQqc7f612mzu6oBPJgxQHfUKNk
AIKD5ob6k7ocLM3FqTEOj8en+GKFAinSCCYd53drcTql9AZaXxLq9HwGg+o06vk6
nS1eqwfjnvOAK0dZII5bBALhBrH6lEZp7g6w0FfGfLl6drPGP682ksvz8QKBgQCC
1w3A7jmUL8rM0kFkk2cmEOw0U5mM/Xi7Wq112Oi5LWPtZvP6pUdBbkw47jud9/Q7
zBnF1qhwaOo9z8+o8gsXDPtiMDg9lHXS1FwN5ksb4NiQpCCXPqMtRiMM3DATnDxT
fGiyvANC51YHhEhQKFMtZ553ujPXdXrRqNBsdCNptQKBgQCTWIjo+8HT1NPe42Ad
K8gWBKxx7W5b8ffk7h4C+zuHgr9f2K0r9TU7tbzexphhWNx/EbcL/ewmgvRSIYc8
Vs0zUimHcwlK6dP1uCywbSXzzK0nTlQHyfDzkbXgx0nuMLHhPzVUzux72bSobpzq
W8YujzKvlP/kQs3cH5mb0sPIKw==
-----END PRIVATE KEY-----"""

TOKEN_URL    = "https://oauthserver.eclinicalworks.com/oauth/oauth2/token"
CLIENT_ID    = "38W1oSu4X_LKOpJEAB-55HwLX9AOdWbNSBkBb1ipdic"  # iss/sub from your JWT
KID          = "connect4.healow.com"
SCOPE        = (
    "system/Patient.read system/Encounter.create "
    "system/Practitioner.read system/PractitionerRole.read "
    "system/DocumentReference.create system/Immunization.read"
)


# ─────────────────────────────────────────────
# STEP 1: Generate client_assertion JWT
# ─────────────────────────────────────────────
def generate_client_assertion():
    now = int(time.time())
    payload = {
        "exp": now + 300,           # 5 min expiry
        "jti": str(uuid.uuid4()),   # unique ID every time
        "iss": CLIENT_ID,
        "sub": CLIENT_ID,
        "aud": TOKEN_URL,
    }
    headers = {
        "alg": "RS384",
        "typ": "JWT",
        "kid": KID,
    }
    token = jwt.encode(
        payload,
        PRIVATE_KEY,
        algorithm="RS384",
        headers=headers,
    )
    return token


# ─────────────────────────────────────────────
# STEP 2: Get Access Token from eCW
# ─────────────────────────────────────────────
def get_access_token():
    client_assertion = generate_client_assertion()

    data = {
        "grant_type":            "client_credentials",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion":      client_assertion,
        "scope":                 SCOPE,
    }

    resp = requests.post(TOKEN_URL, data=data)
    resp.raise_for_status()
    return resp.json()["access_token"]


# ─────────────────────────────────────────────
# FLASK ENDPOINT: GET /call?url=<target_url>
# ─────────────────────────────────────────────
@app.route("/call", methods=["GET"])
def call_with_token():
    target_url = request.args.get("url")
    if not target_url:
        return jsonify({"error": "Missing 'url' query param"}), 400

    try:
        access_token = get_access_token()
    except Exception as e:
        return jsonify({"error": f"Token generation failed: {str(e)}"}), 500

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept":        "application/json",
    }

    try:
        resp = requests.get(target_url, headers=headers)
        return jsonify({
            "status_code": resp.status_code,
            "response":    resp.json() if "json" in resp.headers.get("Content-Type", "") else resp.text,
        })
    except Exception as e:
        return jsonify({"error": f"GET call failed: {str(e)}"}), 500


# ─────────────────────────────────────────────
# BONUS ENDPOINT: GET /token  (just get token)
# ─────────────────────────────────────────────
@app.route("/token", methods=["GET"])
def token_only():
    try:
        access_token = get_access_token()
        return jsonify({"access_token": access_token})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))