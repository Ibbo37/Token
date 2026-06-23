import uuid
import time
import os
import requests
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

# ─────────────────────────────────────────────
# PRIVATE KEY (same for all environments)
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

KID = "connect4.healow.com"

# ─────────────────────────────────────────────
# SCOPES
# ─────────────────────────────────────────────
SINGLE_READ_SCOPE = (
    "system/AllergyIntolerance.read system/Basic.read system/Binary.read "
    "system/CarePlan.read system/CareTeam.read system/Condition.read "
    "system/Coverage.read system/Device.read system/DiagnosticReport.read "
    "system/DocumentReference.read system/Encounter.read system/FamilyMemberHistory.read "
    "system/Goal.read system/Immunization.read system/Location.read "
    "system/Media.read system/Medication.read system/MedicationAdministration.read "
    "system/MedicationDispense.read system/MedicationRequest.read system/Observation.read "
    "system/Organization.read system/Patient.read system/Practitioner.read "
    "system/PractitionerRole.read system/Procedure.read system/Provenance.read "
    "system/Questionnaire.read system/QuestionnaireResponse.read system/RelatedPerson.read "
    "system/ServiceRequest.read system/Specimen.read"
)

SINGLE_CREATE_SCOPE = (
    "system/AllergyIntolerance.create system/Communication.create "
    "system/Condition.create system/Coverage.create system/DocumentReference.create "
    "system/Encounter.create system/Immunization.create system/MedicationRequest.create "
    "system/MedicationStatement.create system/Patient.create "
    "system/QuestionnaireResponse.create system/ServiceRequest.create system/Task.create"
)

SINGLE_PROD_SCOPE = SINGLE_READ_SCOPE + " " + SINGLE_CREATE_SCOPE

BULK_READ_SCOPE = (
    "system/AllergyIntolerance.read system/Binary.read "
    "system/CarePlan.read system/CareTeam.read system/Condition.read "
    "system/Coverage.read system/Device.read system/DiagnosticReport.read "
    "system/DocumentReference.read system/Encounter.read "
    "system/Goal.read system/Group.read system/Immunization.read system/Location.read "
    "system/Media.read system/Medication.read system/MedicationAdministration.read "
    "system/MedicationDispense.read system/MedicationRequest.read system/Observation.read "
    "system/Organization.read system/Patient.read system/Practitioner.read "
    "system/PractitionerRole.read system/Procedure.read system/Provenance.read "
    "system/QuestionnaireResponse.read system/RelatedPerson.read "
    "system/ServiceRequest.read system/Specimen.read"
)

# ─────────────────────────────────────────────
# ENVIRONMENT CONFIG
# ─────────────────────────────────────────────
ENVIRONMENTS = {
    "singleprod": {
        "client_id": "38W1oSu4X_LKOpJEAB-55HwLX9AOdWbNSBkBb1ipdic",
        "token_url": "https://oauthserver.eclinicalworks.com/oauth/oauth2/token",
        "scope":     SINGLE_PROD_SCOPE,
    },
    "singlesandbox": {
        "client_id": "UIcl857ln1yvzPkygxi9x5QMPEOoEnnJy72-gx2FUSw",
        "token_url": "https://staging-oauthserver.ecwcloud.com/oauth/oauth2/token",
        "scope":     SINGLE_READ_SCOPE,
    },
    "bulkprod": {
        "client_id": "tZ_KYyTqt8ryjWjhZpwEDPkDbxAGhh1KqKyr8c8zQas",
        "token_url": "https://oauthserver.eclinicalworks.com/oauth/oauth2/token",
        "scope":     BULK_READ_SCOPE,
    },
    "bulksandbox": {
        "client_id": "0jBDg0uX3WEhhMzFmwqL1PH8LJP5Kx58neJTOWLhHGA",
        "token_url": "https://staging-oauthserver.ecwcloud.com/oauth/oauth2/token",
        "scope":     BULK_READ_SCOPE,
    },
}

BULK_MODES = {"bulkprod", "bulksandbox"}

# ─────────────────────────────────────────────
# TOKEN CACHE
# Har mode ka token alag cache hota hai.
# Token expiry se 60 sec pehle auto-refresh hoga.
# ─────────────────────────────────────────────
token_cache = {}
REFRESH_BUFFER = 60  # seconds before expiry to trigger refresh

def get_cached_token(mode):
    cached = token_cache.get(mode)
    if cached and time.time() < cached["expires_at"] - REFRESH_BUFFER:
        return cached["token"]
    return None

def set_cached_token(mode, token, expires_in=300):
    token_cache[mode] = {
        "token":      token,
        "expires_at": time.time() + expires_in,
    }

# ─────────────────────────────────────────────
# GENERATE JWT client_assertion
# ─────────────────────────────────────────────
def generate_client_assertion(client_id, token_url):
    now = int(time.time())
    payload = {
        "exp": now + 300,
        "jti": str(uuid.uuid4()),
        "iss": client_id,
        "sub": client_id,
        "aud": token_url,
    }
    headers = {
        "alg": "RS384",
        "typ": "JWT",
        "kid": KID,
    }
    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS384", headers=headers)

# ─────────────────────────────────────────────
# FETCH ACCESS TOKEN (with cache + auto-refresh)
# ─────────────────────────────────────────────
def get_access_token(mode):
    # Cache hit — wapas karo bina eCW call ke
    cached = get_cached_token(mode)
    if cached:
        return cached

    # Cache miss ya expiry aane wali hai — naya token lo
    env              = ENVIRONMENTS[mode]
    client_assertion = generate_client_assertion(env["client_id"], env["token_url"])

    data = {
        "grant_type":            "client_credentials",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion":      client_assertion,
        "scope":                 env["scope"],
    }

    resp = requests.post(env["token_url"], data=data, timeout=10)
    resp.raise_for_status()
    result       = resp.json()
    access_token = result["access_token"]
    expires_in   = result.get("expires_in", 300)  # eCW default: 300 sec

    set_cached_token(mode, access_token, expires_in)
    return access_token


# ─────────────────────────────────────────────
# ENDPOINT 1: GET /token?mode=singleprod
# Sirf token return karta hai
# ─────────────────────────────────────────────
@app.route("/token", methods=["GET"])
def token_only():
    mode = request.args.get("mode", "singleprod").lower()
    if mode not in ENVIRONMENTS:
        return jsonify({"error": f"Invalid mode. Choose from: {list(ENVIRONMENTS.keys())}"}), 400
    try:
        access_token = get_access_token(mode)
        return jsonify({
            "mode":         mode,
            "access_token": access_token,
            "scope":        ENVIRONMENTS[mode]["scope"],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# ENDPOINT 2: GET /call?mode=singleprod&url=...
# Single Patient FHIR Call
# ─────────────────────────────────────────────
@app.route("/call", methods=["GET"])
def call_with_token():
    mode       = request.args.get("mode", "singleprod").lower()
    target_url = request.args.get("url")

    if mode not in ENVIRONMENTS:
        return jsonify({"error": f"Invalid mode. Choose from: {list(ENVIRONMENTS.keys())}"}), 400
    if not target_url:
        return jsonify({"error": "Missing 'url' query param"}), 400

    try:
        access_token = get_access_token(mode)
    except Exception as e:
        return jsonify({"error": f"Token generation failed: {str(e)}"}), 500

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept":        "application/json",
    }

    try:
        resp         = requests.get(target_url, headers=headers, timeout=15)
        content_type = resp.headers.get("Content-Type", "")
        return jsonify({
            "mode":        mode,
            "scope":       ENVIRONMENTS[mode]["scope"],
            "status_code": resp.status_code,
            "response":    resp.json() if "json" in content_type else resp.text,
        })
    except Exception as e:
        return jsonify({"error": f"GET call failed: {str(e)}"}), 500


# ─────────────────────────────────────────────
# ENDPOINT 3: GET /bulk?mode=bulkprod&url=...
# Bulk FHIR Kick-off Call
# Headers: Prefer: respond-async, Accept: application/fhir+json
# ─────────────────────────────────────────────
@app.route("/bulk", methods=["GET"])
def bulk_call():
    mode       = request.args.get("mode", "bulkprod").lower()
    target_url = request.args.get("url")

    if mode not in BULK_MODES:
        return jsonify({"error": "Invalid mode for /bulk. Use: bulkprod or bulksandbox"}), 400
    if not target_url:
        return jsonify({"error": "Missing 'url' query param"}), 400

    try:
        access_token = get_access_token(mode)
    except Exception as e:
        return jsonify({"error": f"Token generation failed: {str(e)}"}), 500

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept":        "application/fhir+json",
        "Prefer":        "respond-async",
    }

    try:
        resp         = requests.get(target_url, headers=headers, timeout=15)
        content_type = resp.headers.get("Content-Type", "")
        return jsonify({
            "mode":        mode,
            "scope":       ENVIRONMENTS[mode]["scope"],
            "status_code": resp.status_code,
            "response":    resp.json() if "json" in content_type else resp.text,
        })
    except Exception as e:
        return jsonify({"error": f"Bulk call failed: {str(e)}"}), 500


# ─────────────────────────────────────────────
# ENDPOINT 4: GET /jobstatus?mode=bulkprod&url=...
# Bulk Job Status & Delete
# ─────────────────────────────────────────────
@app.route("/jobstatus", methods=["GET"])
def job_status():
    mode       = request.args.get("mode", "bulkprod").lower()
    target_url = request.args.get("url")

    if mode not in BULK_MODES:
        return jsonify({"error": "Invalid mode for /jobstatus. Use: bulkprod or bulksandbox"}), 400
    if not target_url:
        return jsonify({"error": "Missing 'url' query param"}), 400

    try:
        access_token = get_access_token(mode)
    except Exception as e:
        return jsonify({"error": f"Token generation failed: {str(e)}"}), 500

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept":        "application/json",
    }

    try:
        resp         = requests.get(target_url, headers=headers, timeout=15)
        content_type = resp.headers.get("Content-Type", "")
        return jsonify({
            "mode":        mode,
            "status_code": resp.status_code,
            "response":    resp.json() if "json" in content_type else resp.text,
        })
    except Exception as e:
        return jsonify({"error": f"Job status call failed: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))