import uuid
import time
import os
import asyncio
import logging
import threading
import re
import json
import httpx
import jwt
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from jwt.algorithms import RSAAlgorithm

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("token-service")

# ─────────────────────────────────────────────
# DEBUG TOGGLE STATE
# ─────────────────────────────────────────────
DEBUG_SECRET = os.environ.get("DEBUG_SECRET", "changeme123")  # set this in Render env vars
DEBUG_MODE = os.environ.get("DEBUG_MODE", "false").lower() == "true"

# ─────────────────────────────────────────────
# PRIVATE KEY (loaded from Render env var PRIVATE_KEY)
# Paste the full PEM, including BEGIN/END lines, as the env var value.
# ─────────────────────────────────────────────
def clean_pem(env_name):
    raw = os.environ.get(env_name, "").strip().strip('"').strip("'").replace("\\n", "\n")
    m = re.search(r"-----BEGIN ([A-Z ]+)-----(.*?)-----END \1-----", raw, re.S)
    if not m:
        return raw  # wrong format will fail loudly
    label = m.group(1)
    body = "".join(m.group(2).split())
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"

PRIVATE_KEY = clean_pem("PRIVATE_KEY")
PUBLIC_KEY  = clean_pem("PUBLIC_KEY")  # optional: only used for JWKS / match check

KID = "connect4.healow.com"

# ─────────────────────────────────────────────
# BASE FHIR URLs
# ─────────────────────────────────────────────
FHIR_BASE = {
    "prod":    "https://fhir4.eclinicalworks.com/fhir/r4/",
    "sandbox": "https://staging-fhir.ecwcloud.com/fhir/r4/FFBJCD/",
}

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

SINGLE_PROD_SCOPE = SINGLE_READ_SCOPE

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
        "fhir_base": FHIR_BASE["prod"],
        "scope":     SINGLE_PROD_SCOPE,
    },
    "singlesandbox": {
        "client_id": "UIcl857ln1yvzPkygxi9x5QMPEOoEnnJy72-gx2FUSw",
        "token_url": "https://staging-oauthserver.ecwcloud.com/oauth/oauth2/token",
        "fhir_base": FHIR_BASE["sandbox"],
        "scope":     SINGLE_PROD_SCOPE,  # replace with working_scope_string from /debug/scopecheck
    },
    "bulkprod": {
        "client_id": "tZ_KYyTqt8ryjWjhZpwEDPkDbxAGhh1KqKyr8c8zQas",
        "token_url": "https://oauthserver.eclinicalworks.com/oauth/oauth2/token",
        "fhir_base": FHIR_BASE["prod"],
        "scope":     BULK_READ_SCOPE,
    },
    "bulksandbox": {
        "client_id": "0jBDg0uX3WEhhMzFmwqL1PH8LJP5Kx58neJTOWLhHGA",
        "token_url": "https://staging-oauthserver.ecwcloud.com/oauth/oauth2/token",
        "fhir_base": FHIR_BASE["sandbox"],
        "scope":     BULK_READ_SCOPE,
    },
}

BULK_MODES = {"bulkprod", "bulksandbox"}

# ─────────────────────────────────────────────
# TOKEN CACHE
# ─────────────────────────────────────────────
token_cache = {}

def get_cached_token(mode):
    cached = token_cache.get(mode)
    if cached and time.time() < cached["expires_at"] - 30:
        return cached["token"]
    return None

def set_cached_token(mode, token, expires_in=300):
    token_cache[mode] = {
        "token":      token,
        "expires_at": time.time() + expires_in,
    }

# ─────────────────────────────────────────────
# GENERATE JWT
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
    headers = {"alg": "RS384", "typ": "JWT", "kid": KID}
    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS384", headers=headers)

# ─────────────────────────────────────────────
# FETCH ACCESS TOKEN (async) - supports scope override
# ─────────────────────────────────────────────
async def get_access_token(mode, scope_override=None):
    # Overrides bypass the cache so tests always hit eCW fresh
    if not scope_override:
        cached = get_cached_token(mode)
        if cached:
            return cached

    env              = ENVIRONMENTS[mode]
    client_assertion = generate_client_assertion(env["client_id"], env["token_url"])

    data = {
        "grant_type":            "client_credentials",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion":      client_assertion,
        "scope":                 scope_override or env["scope"],
    }

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(env["token_url"], data=data)
        if resp.status_code != 200:
            raise Exception(f"Token request failed ({resp.status_code}): {resp.text}")
        result       = resp.json()
        access_token = result["access_token"]
        expires_in   = result.get("expires_in", 300)
        if not scope_override:
            set_cached_token(mode, access_token, expires_in)
        return access_token

# ─────────────────────────────────────────────
# ASYNC HELPER
# ─────────────────────────────────────────────
def run_async(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


# ─────────────────────────────────────────────
# DEBUG TOGGLE ENDPOINTS
# ─────────────────────────────────────────────
@app.route("/debug/on", methods=["GET"])
def debug_on():
    global DEBUG_MODE
    if request.args.get("secret") != DEBUG_SECRET:
        return jsonify({"error": "unauthorized"}), 403
    DEBUG_MODE = True
    return jsonify({"debug_mode": DEBUG_MODE})

@app.route("/debug/off", methods=["GET"])
def debug_off():
    global DEBUG_MODE
    if request.args.get("secret") != DEBUG_SECRET:
        return jsonify({"error": "unauthorized"}), 403
    DEBUG_MODE = False
    return jsonify({"debug_mode": DEBUG_MODE})

@app.route("/debug/status", methods=["GET"])
def debug_status():
    info = {"debug_mode": DEBUG_MODE}
    first = os.environ.get("PRIVATE_KEY", "").strip().splitlines()[:1]
    info["private_key_env_first_line"] = first[0][:40] if first else None
    priv = None
    try:
        priv = serialization.load_pem_private_key(PRIVATE_KEY.encode(), password=None)
        info["private_key_parses"] = True
    except Exception as e:
        info["private_key_parses"] = False
        info["private_key_error"] = str(e)[:100]
    if PUBLIC_KEY.strip():
        try:
            pub = serialization.load_pem_public_key(PUBLIC_KEY.encode())
            info["public_key_parses"] = True
            if priv:
                info["public_matches_private"] = (
                    pub.public_numbers() == priv.public_key().public_numbers()
                )
        except Exception as e:
            info["public_key_parses"] = False
            info["public_key_error"] = str(e)[:100]
    return jsonify(info)


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    try:
        if PUBLIC_KEY.strip():
            pub = serialization.load_pem_public_key(PUBLIC_KEY.encode())
        else:
            pub = serialization.load_pem_private_key(PRIVATE_KEY.encode(), password=None).public_key()
        jwk = json.loads(RSAAlgorithm.to_jwk(pub))
        jwk.update({"kid": KID, "alg": "RS384", "use": "sig"})
        return jsonify({"keys": [jwk]})
    except Exception as e:
        return jsonify({"error": str(e)[:120]}), 500


# ─────────────────────────────────────────────
# DEBUG: test every scope individually
# GET /debug/scopecheck?mode=singlesandbox&secret=...
# ─────────────────────────────────────────────
@app.route("/debug/scopecheck", methods=["GET"])
def scope_check():
    if request.args.get("secret") != DEBUG_SECRET:
        return jsonify({"error": "unauthorized"}), 403

    mode = request.args.get("mode", "singlesandbox").lower()
    if mode not in ENVIRONMENTS:
        return jsonify({"error": "invalid mode"}), 400

    env    = ENVIRONMENTS[mode]
    scopes = env["scope"].split()

    async def _check_all():
        sem = asyncio.Semaphore(5)

        async def check(scope):
            async with sem:
                assertion = generate_client_assertion(env["client_id"], env["token_url"])
                data = {
                    "grant_type":            "client_credentials",
                    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    "client_assertion":      assertion,
                    "scope":                 scope,
                }
                async with httpx.AsyncClient(timeout=15) as client:
                    r = await client.post(env["token_url"], data=data)
                    return scope, r.status_code, r.text[:150]

        return await asyncio.gather(*[check(s) for s in scopes])

    try:
        results = run_async(_check_all())
        valid   = [s for s, code, _ in results if code == 200]
        invalid = [{"scope": s, "status": code, "detail": t} for s, code, t in results if code != 200]
        return jsonify({
            "mode":                 mode,
            "valid_count":          len(valid),
            "invalid":              invalid,
            "working_scope_string": " ".join(valid),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# ENDPOINT 1: GET /token?mode=singleprod
# Optional: &scope=... (only while debug mode is on)
# ─────────────────────────────────────────────
@app.route("/token", methods=["GET"])
def token_only():
    mode           = request.args.get("mode", "singleprod").lower()
    scope_override = request.args.get("scope")

    if mode not in ENVIRONMENTS:
        return jsonify({"error": f"Invalid mode. Choose from: {list(ENVIRONMENTS.keys())}"}), 400

    if scope_override and not DEBUG_MODE:
        return jsonify({"error": "scope override requires debug mode"}), 403

    try:
        start        = time.time()
        access_token = run_async(get_access_token(mode, scope_override))
        elapsed_ms   = round((time.time() - start) * 1000)
        return jsonify({
            "mode":         mode,
            "access_token": access_token,
            "scope":        scope_override or ENVIRONMENTS[mode]["scope"],
            "response_ms":  elapsed_ms,
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

    async def _call():
        token = await get_access_token(mode)
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept":        "application/json",
        }
        async with httpx.AsyncClient(timeout=15) as client:
            return await client.get(target_url, headers=headers)

    try:
        start   = time.time()
        resp    = run_async(_call())
        elapsed = round((time.time() - start) * 1000)
        ct      = resp.headers.get("content-type", "")
        return jsonify({
            "mode":        mode,
            "fhir_base":   ENVIRONMENTS[mode]["fhir_base"],
            "scope":       ENVIRONMENTS[mode]["scope"],
            "status_code": resp.status_code,
            "response_ms": elapsed,
            "response":    resp.json() if "json" in ct else resp.text,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# ENDPOINT 3: GET /bulk?mode=bulkprod&url=...
# Bulk FHIR Kick-off
# ─────────────────────────────────────────────
@app.route("/bulk", methods=["GET"])
def bulk_call():
    mode       = request.args.get("mode", "bulkprod").lower()
    target_url = request.args.get("url")

    if mode not in BULK_MODES:
        return jsonify({"error": "Invalid mode for /bulk. Use: bulkprod or bulksandbox"}), 400
    if not target_url:
        return jsonify({"error": "Missing 'url' query param"}), 400

    async def _call():
        token = await get_access_token(mode)
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept":        "application/fhir+json",
            "Prefer":        "respond-async",
        }
        async with httpx.AsyncClient(timeout=15) as client:
            return await client.get(target_url, headers=headers)

    try:
        start   = time.time()
        resp    = run_async(_call())
        elapsed = round((time.time() - start) * 1000)
        ct      = resp.headers.get("content-type", "")
        return jsonify({
            "mode":        mode,
            "fhir_base":   ENVIRONMENTS[mode]["fhir_base"],
            "scope":       ENVIRONMENTS[mode]["scope"],
            "status_code": resp.status_code,
            "response_ms": elapsed,
            "response":    resp.json() if "json" in ct else resp.text,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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

    async def _call():
        token = await get_access_token(mode)
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept":        "application/json",
        }
        async with httpx.AsyncClient(timeout=15) as client:
            return await client.get(target_url, headers=headers)

    try:
        start   = time.time()
        resp    = run_async(_call())
        elapsed = round((time.time() - start) * 1000)
        ct      = resp.headers.get("content-type", "")
        return jsonify({
            "mode":        mode,
            "status_code": resp.status_code,
            "response_ms": elapsed,
            "response":    resp.json() if "json" in ct else resp.text,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# KEEP-ALIVE (Render free tier)
# ─────────────────────────────────────────────
def keep_alive():
    base = os.environ.get("RENDER_EXTERNAL_URL")
    if not base:
        return
    while True:
        time.sleep(300)
        try:
            httpx.get(f"{base}/debug/status", timeout=10)
        except Exception:
            pass

threading.Thread(target=keep_alive, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
